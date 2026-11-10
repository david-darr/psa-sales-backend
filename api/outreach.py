"""Safe, observable bulk outreach.

A rep picks recipients, we validate every one of them server-side (ownership,
eligibility, daily limit), persist a batch with one row per recipient, and a
background thread sends them one at a time over a single reused SMTP connection.
All state lives in the database so any gunicorn worker can report on a batch and a
batch that stops making progress is reported as ``stalled`` and can be retried.

Message rendering, SentEmail / SentMessage logging and the SMTP helpers are the
existing ones in api.py; this module only orchestrates them.
"""
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytz

from flask import current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from itsdangerous import BadSignature
from sqlalchemy import and_, case, exists, func, or_, select, text, update
from sqlalchemy.orm import aliased

from .crm import followup_due_filter

log = logging.getLogger(__name__)

DEFAULT_DAILY_LIMIT = 150
DEFAULT_SEND_DELAY_SECONDS = 1.0
RECENT_CONTACT_DAYS = 3
STALL_AFTER = timedelta(minutes=15)
MAX_BATCH_SCHOOLS = 500
MAX_PREVIEW_SCHOOLS = 100
MAX_ERROR_LENGTH = 500
KINDS = ('initial', 'followup', 'custom')
DEFAULT_SUBJECT = "Let's Connect! PSA Programs"

REPLIED_STAGES = frozenset({'replied', 'meeting', 'partner'})
CLOSED_STAGES = frozenset({'not_interested', 'former'})
SUPPRESSION_KINDS = ('unsubscribed', 'do_not_contact')

# Order decides which blocker is reported as the single "reason" for a skipped school.
BLOCKER_ORDER = ('missing_email', 'unsubscribed', 'closed', 'replied',
                 'recently_contacted', 'not_due', 'in_flight', 'no_mailbox', 'not_owner')
PREVIEW_WARNINGS = ('missing_email', 'unsubscribed', 'closed', 'replied',
                    'recently_contacted', 'not_due', 'in_flight')

# Filled in by register_outreach_routes (the models need the app's db object).
svc = None
db = None
OutreachBatch = None
OutreachRecipient = None
OutreachAttempt = None


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

def _build_models():
    class _OutreachBatch(db.Model):
        __tablename__ = 'outreach_batches'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        kind = db.Column(db.String(12), nullable=False)
        status = db.Column(db.String(12), nullable=False, default='queued')
        subject = db.Column(db.Text)
        attachments = db.Column(db.Boolean, nullable=False, default=False)
        template_snapshot = db.Column(db.Text)
        campaign_id = db.Column(db.String(36))
        paused_reason = db.Column(db.Text)
        lease_owner = db.Column(db.String(36))
        lease_until = db.Column(db.DateTime)
        available_at = db.Column(db.DateTime)
        worker_token = db.Column(db.String(36))
        created_at = db.Column(db.DateTime, nullable=False, default=lambda: svc.utc_now())
        started_at = db.Column(db.DateTime)
        finished_at = db.Column(db.DateTime)
        heartbeat_at = db.Column(db.DateTime, nullable=False, default=lambda: svc.utc_now())
        owner = db.relationship('User')

    class _OutreachRecipient(db.Model):
        __tablename__ = 'outreach_recipients'
        id = db.Column(db.Integer, primary_key=True)
        batch_id = db.Column(db.Integer, db.ForeignKey('outreach_batches.id', ondelete='CASCADE'), nullable=False)
        position = db.Column(db.Integer, nullable=False, default=0)
        school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='SET NULL'))
        school_name = db.Column(db.Text, nullable=False)
        email = db.Column(db.Text, nullable=False, default='')
        status = db.Column(db.String(12), nullable=False, default='queued')
        error = db.Column(db.Text)
        attempts = db.Column(db.Integer, nullable=False, default=0)
        attempted_at = db.Column(db.DateTime)
        sent_email_id = db.Column(db.Integer, db.ForeignKey('sent_emails.id', ondelete='SET NULL'))
        sent_at = db.Column(db.DateTime)
        subject = db.Column(db.Text)
        body = db.Column(db.Text)
        attachments = db.Column(db.Text)
        ownership_version = db.Column(db.Integer)
        followup_of_email_id = db.Column(db.Integer, db.ForeignKey('sent_emails.id', ondelete='SET NULL'))
        contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'))
        contact_link_id = db.Column(db.Integer, db.ForeignKey('school_contacts.id', ondelete='SET NULL'))
        contact_version = db.Column(db.Integer)
        link_version = db.Column(db.Integer)

    class _OutreachAttempt(db.Model):
        __tablename__ = 'outreach_send_attempts'
        id = db.Column(db.Integer, primary_key=True)
        recipient_id = db.Column(db.Integer, db.ForeignKey('outreach_recipients.id'), nullable=False)
        attempt_number = db.Column(db.Integer, nullable=False)
        started_at = db.Column(db.DateTime, nullable=False, default=now)
        status = db.Column(db.String(12), nullable=False, default='sending')
        __table_args__ = (db.UniqueConstraint('recipient_id', 'attempt_number', name='uq_recipient_attempt'),)

    return _OutreachBatch, _OutreachRecipient, _OutreachAttempt


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def now():
    return svc.utc_now()


def iso(value):
    """New endpoints emit explicit UTC ('Z') so browsers never read them as local time."""
    return value.isoformat() + 'Z' if value else None


def daily_limit():
    try:
        value = int(os.getenv('OUTREACH_DAILY_LIMIT', ''))
        if value > 0:
            return value
    except ValueError:
        pass
    return DEFAULT_DAILY_LIMIT


def send_delay():
    try:
        return max(0.0, float(os.getenv('OUTREACH_SEND_DELAY', DEFAULT_SEND_DELAY_SECONDS)))
    except ValueError:
        return DEFAULT_SEND_DELAY_SECONDS


def day_start():
    return day_bounds()[0]


def day_bounds():
    local = now().replace(tzinfo=timezone.utc).astimezone(ZoneInfo('America/New_York'))
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    return tuple(value.astimezone(timezone.utc).replace(tzinfo=None) for value in (start, end))


def current_user():
    try:
        return db.session.get(svc.User, int(get_jwt_identity()))
    except (TypeError, ValueError):
        return None


def clean_error(error):
    text = ' '.join(str(error).split()) or error.__class__.__name__
    return text[:MAX_ERROR_LENGTH]


def valid_subject(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 240 and '\n' not in value and '\r' not in value


def valid_body(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 20000


def apply_vars(text, school, user):
    """The same [placeholder] substitution the custom-email endpoints use."""
    return (text
            .replace('[school_name]', school.school_name or '')
            .replace('[contact_name]', school.contact_name or 'Director/Administrator')
            .replace('[user_name]', user.name or '')
            .replace('[user_email]', user.email or ''))


def sent_today(user_id):
    """Outbound sends today (UTC) from this user's mailbox: outreach rows plus follow-ups/replies."""
    start = day_start()
    outreach = db.session.query(func.count(svc.SentEmail.id)).filter(
        svc.SentEmail.user_id == user_id, svc.SentEmail.sent_at >= start).scalar() or 0
    other = db.session.query(func.count(svc.SentMessage.id)).join(
        svc.SentEmail, svc.SentEmail.id == svc.SentMessage.sent_email_id).filter(
        svc.SentEmail.user_id == user_id, svc.SentMessage.sent_at >= start,
        svc.SentMessage.kind != 'outreach').scalar() or 0
    tests = db.session.query(func.count(OutreachRecipient.id)).join(OutreachBatch).filter(
        OutreachBatch.user_id == user_id, OutreachBatch.kind == 'test',
        OutreachRecipient.status == 'sent', OutreachRecipient.sent_at >= start).scalar() or 0
    uncertain = uncertain_attempts(user_id)
    legacy_uncertain = db.session.query(func.count(OutreachRecipient.id)).join(OutreachBatch).filter(
        OutreachBatch.user_id == user_id, OutreachRecipient.status == 'unconfirmed',
        ~exists().where(OutreachAttempt.recipient_id == OutreachRecipient.id),
        func.coalesce(OutreachRecipient.attempted_at, OutreachBatch.created_at) >= start).scalar() or 0
    return outreach + other + tests + uncertain + legacy_uncertain


def uncertain_attempts(user_id, campaign_id=None):
    query = db.session.query(func.count(OutreachAttempt.id)).join(OutreachRecipient).join(OutreachBatch).filter(
        OutreachBatch.user_id == user_id, OutreachAttempt.started_at >= day_start(),
        or_(OutreachAttempt.status == 'unconfirmed', and_(OutreachAttempt.status == 'sending',
            OutreachAttempt.started_at < now() - STALL_AFTER)))
    if campaign_id is not None: query = query.filter(OutreachBatch.campaign_id == campaign_id)
    return query.scalar() or 0


def reserved_count(user_id):
    """Recipients already promised to live batches, so two batches cannot overshoot the limit."""
    return db.session.query(func.count(OutreachRecipient.id)).join(
        OutreachBatch, OutreachBatch.id == OutreachRecipient.batch_id).filter(
        OutreachBatch.user_id == user_id,
        OutreachBatch.status.in_(('queued', 'sending')),
        OutreachBatch.heartbeat_at >= now() - STALL_AFTER,
        OutreachRecipient.status.in_(('queued', 'sending'))).scalar() or 0


def campaign_used(user_id, campaign_id, include_reservations=True):
    actual = or_(and_(OutreachRecipient.status == 'sent', OutreachRecipient.sent_at >= day_start()),
                 and_(OutreachRecipient.status == 'unconfirmed',
                      ~exists().where(OutreachAttempt.recipient_id == OutreachRecipient.id),
                      func.coalesce(OutreachRecipient.attempted_at, OutreachBatch.created_at) >= day_start()))
    if include_reservations:
        actual = or_(actual, and_(OutreachRecipient.status.in_(('queued', 'sending')),
            OutreachBatch.status.in_(('queued', 'sending')), OutreachBatch.heartbeat_at >= now() - STALL_AFTER))
    counted = db.session.query(func.count(OutreachRecipient.id)).join(OutreachBatch).filter(
        OutreachBatch.user_id == user_id, OutreachBatch.campaign_id == campaign_id, actual).scalar() or 0
    return counted + uncertain_attempts(user_id, campaign_id)


def limits_for(user):
    limit = mailbox_limit()
    sent = sent_today(user.id)
    reserved = reserved_count(user.id)
    return {
        'daily_limit': limit,
        'sent_today': sent,
        'remaining': max(0, limit - sent - reserved),
        'reserved': reserved,
        'resets_at': iso(day_bounds()[1]),
        'time_zone': 'America/New_York',
        'mailbox_connected': bool(user.email_password),
    }


def mailbox_limit():
    try: configured = max(1, int(os.getenv('OUTREACH_MAILBOX_DAILY_LIMIT', str(daily_limit()))))
    except ValueError: configured = daily_limit()
    return min(daily_limit(), configured)


def effective_status(batch):
    if batch.status == 'queued' and batch.available_at and batch.available_at > now():
        return 'queued'
    if batch.status in ('queued', 'sending') and batch.heartbeat_at and now() - batch.heartbeat_at > STALL_AFTER:
        return 'stalled'
    return batch.status


# ---------------------------------------------------------------------------
# Eligibility: one query set for any number of schools
# ---------------------------------------------------------------------------

def school_rows_query():
    """Schools with their latest sent email, contact history, suppression flag and owner mailbox."""
    S, SE, SM, SA = svc.SalesSchool, svc.SentEmail, svc.SentMessage, svc.SchoolActivity
    Owner, Latest = aliased(svc.User), aliased(SE)
    email_agg = db.session.query(
        SE.sales_school_id.label('sid'),
        func.max(SE.id).label('latest_id'),
        func.max(SE.sent_at).label('last_email_at'),
        func.max(case((SE.responded.is_(True), 1), else_=0)).label('responded_any'),
    ).filter(SE.sales_school_id.isnot(None)).group_by(SE.sales_school_id).subquery('email_agg')
    message_agg = db.session.query(
        SE.sales_school_id.label('sid'), func.max(SM.sent_at).label('last_message_at'),
    ).join(SM, SM.sent_email_id == SE.id).filter(
        SE.sales_school_id.isnot(None)).group_by(SE.sales_school_id).subquery('message_agg')
    suppressed = or_(exists().where(SA.sales_school_id == S.id, SA.kind.in_(SUPPRESSION_KINDS)).correlate(S),
        exists().where(svc.Contact.email == func.lower(func.trim(S.email)), svc.Contact.do_not_contact.is_(True)).correlate(S))
    query = db.session.query(
        S, Latest, email_agg.c.last_email_at, email_agg.c.responded_any, message_agg.c.last_message_at,
        suppressed.label('suppressed'), Owner.name.label('owner_name'),
        (func.coalesce(func.length(Owner.email_password), 0) > 0).label('has_mailbox'),
    ).join(Owner, Owner.id == S.user_id
    ).outerjoin(email_agg, email_agg.c.sid == S.id
    ).outerjoin(Latest, Latest.id == email_agg.c.latest_id
    ).outerjoin(message_agg, message_agg.c.sid == S.id)
    return query, Latest, email_agg


def chosen_email(school, latest, kind):
    """Follow-ups go back to the address that was originally emailed; others to the first valid one."""
    if kind == 'followup' and latest is not None:
        return (latest.school_email or '').strip().casefold()
    for item in school.get_all_emails():
        if svc.valid_email(item):
            return item.strip().casefold()
    return (school.email or '').strip().casefold()


def in_flight_school_ids(school_ids):
    """Schools that already have an email waiting or being sent in an unfinished batch."""
    school_ids = list(school_ids)
    if not school_ids:
        return set()
    rows = db.session.query(OutreachRecipient.school_id).join(
        OutreachBatch, OutreachBatch.id == OutreachRecipient.batch_id).filter(
        OutreachRecipient.school_id.in_(school_ids),
        OutreachRecipient.status.in_(('queued', 'sending')),
        OutreachBatch.status.in_(('queued', 'sending'))).distinct().all()
    return {school_id for (school_id,) in rows}


def compute_blockers(kind, row, viewer_id, in_flight=frozenset()):
    school, latest, last_email_at, responded_any, last_message_at, suppressed, _owner, has_mailbox = row
    current = now()
    blockers = set()
    if school.id in in_flight:
        blockers.add('in_flight')
    if not svc.valid_email(chosen_email(school, latest, kind)):
        blockers.add('missing_email')
    if suppressed:
        blockers.add('unsubscribed')
    if normalized_email := chosen_email(school, latest, kind):
        if normalized_email.strip().casefold() != (school.email or '').strip().casefold() and svc.contact_is_blocked(normalized_email):
            blockers.add('unsubscribed')
    if school.status in CLOSED_STAGES:
        blockers.add('closed')
    if school.status in REPLIED_STAGES or responded_any:
        blockers.add('replied')
    last_contact = max([item for item in (last_email_at, last_message_at) if item], default=None)
    if last_contact and current - last_contact < timedelta(days=RECENT_CONTACT_DAYS):
        blockers.add('recently_contacted')
    if kind == 'initial' and last_email_at and current - last_email_at < timedelta(days=svc.FOLLOWUP_MAX_AGE_DAYS):
        blockers.add('recently_contacted')
    if kind == 'followup':
        # The follow-up must continue the original rep's own thread with the same rules as /api/send-followup.
        due_at = svc.followup_due_at(latest) if latest is not None else None
        if (latest is None or due_at is None or latest.user_id != school.user_id
                or current < due_at
                or latest.sent_at < current - timedelta(days=svc.FOLLOWUP_MAX_AGE_DAYS)):
            blockers.add('not_due')
    if not has_mailbox:
        blockers.add('no_mailbox')
    if school.user_id != viewer_id:
        blockers.add('not_owner')
    return [name for name in BLOCKER_ORDER if name in blockers]


def combined_files(defaults, extras):
    return list({item['id']: item for item in [*defaults, *extras]}.values())


def build_content(kind, user, school, latest, subject, body, attachments, template=None, catalog_files=None):
    """Render one recipient's message with the existing templates; never duplicates them."""
    if template:
        from .template_library import render_copy
        if kind == 'followup' and (latest is None or template['step'] != svc.followup_stage(latest) + 1):
            raise ValueError('The follow-up template step does not match ' + school.school_name + '. Select recipients at the same step.')
        rendered_subject, text = render_copy(subject if subject is not None else template['subject'],
                                            body if body is not None else template['body'], school, user)
        return {'subject': rendered_subject, 'body': text,
                'pdf_files': ['template-asset:' + item['id'] for item in combined_files(template.get('attachments', []), catalog_files or [])],
                'attachment_names': [item['name'] for item in combined_files(template.get('attachments', []), catalog_files or [])],
                'template': template, 'ownership_version': school.ownership_version}
    pdf_files = []
    if kind == 'followup':
        if body:
            text = apply_vars(body, school, user)
        elif latest is not None:
            text = svc.followup_message(user, latest)
        else:
            text = ''
        rendered_subject = apply_vars(subject, school, user) if subject else svc.FOLLOWUP_SUBJECT
    else:
        rendered_subject = apply_vars(subject or DEFAULT_SUBJECT, school, user)
        template_job = svc.build_outreach_jobs(user, [school], rendered_subject, False)[0]
        text = apply_vars(body, school, user) if body else template_job['body']
        wants_files = attachments is True or (attachments is None and kind == 'initial')
        if wants_files:
            pdf_files = list(template_job['pdf_files'])
    if catalog_files is not None:
        pdf_files = ['template-asset:' + item['id'] for item in catalog_files]
    return {'subject': rendered_subject, 'body': text, 'pdf_files': pdf_files,
            'attachment_names': [item['name'] for item in catalog_files] if catalog_files is not None else pdf_files,
            'ownership_version': school.ownership_version}


def fingerprint(email_address, content):
    original = svc.outreach_fingerprint({
        'to_email': email_address, 'subject': content['subject'],
        'body': content['body'], 'pdf_files': content['pdf_files']})
    import hashlib
    metadata = {'template': content.get('template'), 'ownership_version': content['ownership_version']}
    return hashlib.sha256((original + json.dumps(metadata, sort_keys=True)).encode()).hexdigest()


def parse_request_options(data, max_schools, preview_limit=MAX_PREVIEW_SCHOOLS):
    """Validate the fields shared by preview and batch creation. Returns (options, error_response)."""
    if not isinstance(data, dict):
        return None, (jsonify(error='Supply an outreach request object'), 400)
    ids = data.get('school_ids')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= max_schools
            or any(type(value) is not int or value < 1 for value in ids)):
        return None, (jsonify(error=f'Select between 1 and {max_schools} schools'), 400)
    kind = data.get('kind')
    if kind not in KINDS:
        return None, (jsonify(error="Choose a kind: 'initial', 'followup' or 'custom'"), 400)
    subject, body, attachments = data.get('subject'), data.get('body'), data.get('attachments')
    if subject is not None and not valid_subject(subject):
        return None, (jsonify(error='Enter a valid subject'), 400)
    if body is not None and not valid_body(body):
        return None, (jsonify(error='Enter a valid message body'), 400)
    if attachments is not None and not isinstance(attachments, bool):
        return None, (jsonify(error='attachments must be true or false'), 400)
    if kind == 'custom' and (subject is None or body is None):
        return None, (jsonify(error='A custom email needs a subject and a message'), 400)
    try:
        template = svc.resolve_mail_template(data)
        catalog_files = svc.select_catalog_attachments(data['attachment_ids']) if 'attachment_ids' in data else None
        files = combined_files((template or {}).get('attachments', []), catalog_files or [])
        if len(files) > 3 or sum(item['bytes'] for item in files) > 15 * 1024 * 1024:
            raise ValueError('Choose up to three PDFs, totaling at most 15 MB including template defaults.')
        if catalog_files is not None and attachments:
            raise ValueError('Select catalog PDFs instead of the all-flyers checkbox.')
    except ValueError as exc:
        return None, (jsonify(error=str(exc)), 400)
    if (template or catalog_files) and len(ids) > preview_limit:
        return None, (jsonify(error=f'Shared-template batches require review of every recipient. Select at most {preview_limit} schools.'), 400)
    unique = list(dict.fromkeys(ids))
    return {'ids': unique, 'kind': kind, 'subject': subject, 'body': body, 'attachments': attachments, 'template': template, 'catalog_files': catalog_files}, None


def owned_rows(user, ids):
    """Rows for exactly the requested schools, or None if any is missing or not the sender's."""
    query, _latest, _agg = school_rows_query()
    rows = query.filter(svc.SalesSchool.id.in_(ids)).all()
    if len(rows) != len(ids) or any(row[0].user_id != user.id for row in rows):
        return None
    by_id = {row[0].id: row for row in rows}
    return [by_id[school_id] for school_id in ids]


# ---------------------------------------------------------------------------
# Preview
# ---------------------------------------------------------------------------

def preview_response(data):
    """POST /api/email-preview with {school_ids, kind, subject?, body?}."""
    options, error = parse_request_options(data, MAX_PREVIEW_SCHOOLS)
    if error:
        return error
    user = current_user()
    if not user:
        return jsonify(error='User not found'), 404
    if data.get('contact_mode') is True:
        return svc.preview_contact_outreach(user, options, data)
    rows = owned_rows(user, options['ids'])
    if rows is None:
        return jsonify(error='Send only to schools assigned to you'), 403
    kind = options['kind']
    previews, fingerprints = [], {}
    busy = in_flight_school_ids(row[0].id for row in rows)
    for row in rows:
        school, latest = row[0], row[1]
        blockers = compute_blockers(kind, row, user.id, busy)
        try:
            content = build_content(kind, user, school, latest, options['subject'], options['body'], options['attachments'], options.get('template'), options.get('catalog_files'))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        address = chosen_email(school, latest, kind)
        plain, html_body = svc.render_body_parts(content['body'])
        warnings = [name for name in blockers if name in PREVIEW_WARNINGS]
        if not (school.contact_name or '').strip():
            warnings.append('empty_greeting')
        fingerprints[f'{school.id}:{address}'] = fingerprint(address, content)
        previews.append({
            'school_id': school.id, 'school_name': school.school_name, 'email': address,
            'subject': content['subject'], 'body_html': html_body, 'body_text': plain,
            'warnings': warnings, 'attachments': content['attachment_names'],
            'eligible': not blockers, 'blockers': blockers,
        })
    token = svc.outreach_review_signer().dumps({'uid': user.id, 'fingerprints': fingerprints})
    return jsonify(previews=previews, preview_token=token)


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def counts_for(batch_ids):
    counts = {batch_id: {} for batch_id in batch_ids}
    if batch_ids:
        for batch_id, status, count in db.session.query(
                OutreachRecipient.batch_id, OutreachRecipient.status, func.count(OutreachRecipient.id)
        ).filter(OutreachRecipient.batch_id.in_(batch_ids)).group_by(
                OutreachRecipient.batch_id, OutreachRecipient.status).all():
            counts[batch_id][status] = count
    return counts


def batch_dict(batch, counts, recipients=None):
    data = {
        'id': batch.id, 'kind': batch.kind, 'status': effective_status(batch),
        'total': sum(counts.values()),
        'sent': counts.get('sent', 0), 'failed': counts.get('failed', 0), 'skipped': counts.get('skipped', 0),
        'queued': counts.get('queued', 0), 'sending': counts.get('sending', 0),
        'cancelled': counts.get('cancelled', 0), 'unconfirmed': counts.get('unconfirmed', 0),
        'created_at': iso(batch.created_at), 'finished_at': iso(batch.finished_at),
        'user_id': batch.user_id, 'owner_name': batch.owner.name if batch.owner else None,
        'campaign_id': batch.campaign_id, 'paused_reason': batch.paused_reason,
    }
    if batch.template_snapshot:
        data['template'] = json.loads(batch.template_snapshot)
    if recipients is not None:
        attempts = OutreachAttempt.query.filter(OutreachAttempt.recipient_id.in_([r.id for r in recipients])).order_by(
            OutreachAttempt.recipient_id, OutreachAttempt.attempt_number).all()
        attempt_history = {}
        for attempt in attempts:
            attempt_history.setdefault(attempt.recipient_id, []).append(dict(number=attempt.attempt_number,
                status=attempt.status, started_at=iso(attempt.started_at)))
        data['recipients'] = [{
            'id': item.id, 'contact_id': item.contact_id,
            'school_id': item.school_id, 'school_name': item.school_name, 'email': item.email,
            'status': item.status, 'error': item.error, 'sent_at': iso(item.sent_at),
            'attempts': attempt_history.get(item.id, []),
        } for item in recipients]
    return data


def accessible_batch(user, batch_id, lock=False):
    query = db.session.query(OutreachBatch).filter(OutreachBatch.id == batch_id)
    if not user.admin:
        query = query.filter(OutreachBatch.user_id == user.id)
    if lock:
        query = query.with_for_update()
    return query.first()


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def start_worker(app, batch_id, token):
    """Durable queue only. The dedicated worker polls committed batches."""
    return None


def run_batch(app, batch_id, token, delay=None, max_recipients=None):
    """Thread entry point. Never raises; every failure is recorded on the recipient or batch."""
    with app.app_context():
        try:
            _process_batch(batch_id, token, send_delay() if delay is None else delay, max_recipients)
        except Exception:
            db.session.rollback()
            log.exception('Outreach batch %s worker crashed', batch_id)
        finally:
            db.session.remove()


def _touch(batch_id):
    db.session.execute(update(OutreachBatch).where(OutreachBatch.id == batch_id).values(heartbeat_at=now(),
        lease_until=case((OutreachBatch.lease_owner.isnot(None), now()+timedelta(minutes=5)), else_=None)))


def _fail_remaining(batch_id, error):
    db.session.execute(update(OutreachRecipient).where(
        OutreachRecipient.batch_id == batch_id, OutreachRecipient.status == 'queued'
    ).values(status=case((exists().where(OutreachAttempt.recipient_id == OutreachRecipient.id,
        OutreachAttempt.status == 'unconfirmed'), 'unconfirmed'), else_='failed'), error=clean_error(error)))
    db.session.commit()


def _process_batch(batch_id, token, delay, max_recipients=None):
    claimed = db.session.execute(update(OutreachBatch).where(
        OutreachBatch.id == batch_id, OutreachBatch.worker_token == token, OutreachBatch.status == 'queued'
    ).values(status='sending', started_at=func.coalesce(OutreachBatch.started_at, now()),
             heartbeat_at=now())).rowcount
    db.session.commit()
    if not claimed:
        return  # another worker owns this batch, or it was cancelled before we started
    batch = db.session.get(OutreachBatch, batch_id)
    user = db.session.get(svc.User, batch.user_id)
    try:
        password = svc.user_mail_password(user)
    except Exception:
        _fail_remaining(batch_id, 'Email connection unavailable. Contact your PSA administrator.')
        _finish(batch_id, token)
        return
    sender = svc.SmtpSender(user.email, password, user.name)
    # Plain values: the session is rolled back around every send, which would otherwise reload these rows each time.
    batch_ctx = SimpleNamespace(id=batch.id, kind=batch.kind, user_id=batch.user_id, campaign_id=batch.campaign_id)
    user_id = user.id
    quota = {'sent': None, 'since_check': 0}
    pause = False
    chunk_sent = 0
    processed = 0
    contact_mode = batch_ctx.kind not in ('reply', 'test')
    try:
        while True:
            if pause and delay:
                # Hand the pooled database connection back while idle so many batches cannot starve the web app.
                db.session.rollback()
                time.sleep(delay)
            db.session.expire_all()
            live = db.session.execute(select(OutreachBatch.status, OutreachBatch.worker_token).where(
                OutreachBatch.id == batch_id)).one_or_none()
            if live is None or live.worker_token != token or live.status != 'sending':
                break  # cancelled, retried by a newer worker, or deleted
            if hasattr(svc,'campaign_dispatch_gate') and svc.campaign_dispatch_gate(batch_id):break
            if max_recipients is not None and processed >= max_recipients:
                if not OutreachRecipient.query.filter_by(batch_id=batch_id, status='queued').first(): break
                db.session.execute(update(OutreachBatch).where(OutreachBatch.id==batch_id,
                    OutreachBatch.worker_token==token, OutreachBatch.status=='sending').values(
                    status='queued', lease_owner=None, lease_until=None, heartbeat_at=now()))
                db.session.commit(); break
            if contact_mode and batch_ctx.kind != 'reply' and chunk_sent >= 5:
                db.session.rollback()
                try:
                    state = svc.sync_user_mailbox(db.session.get(svc.User, user_id))
                    ready = state.get('ready', False)
                except Exception:
                    ready = False
                    db.session.rollback()
                if not ready:
                    db.session.execute(update(OutreachBatch).where(OutreachBatch.id == batch_id,
                        OutreachBatch.status == 'sending').values(status='paused', paused_reason='Inbox check incomplete. Check replies, then review remaining messages.'))
                    db.session.commit()
                    break
                chunk_sent = 0
                continue  # sync may have paused/cancelled the batch; re-read it before claiming another row
            recipient = db.session.execute(select(
                OutreachRecipient.id, OutreachRecipient.school_id, OutreachRecipient.email,
                OutreachRecipient.subject, OutreachRecipient.body, OutreachRecipient.attachments,
                OutreachRecipient.followup_of_email_id, OutreachRecipient.ownership_version,
                OutreachRecipient.contact_id, OutreachRecipient.contact_link_id,
                OutreachRecipient.contact_version, OutreachRecipient.link_version,
            ).where(OutreachRecipient.batch_id == batch_id, OutreachRecipient.status == 'queued').order_by(
                OutreachRecipient.position, OutreachRecipient.id).limit(1)).one_or_none()
            if recipient is None:
                break
            claimed_row = db.session.execute(update(OutreachRecipient).where(
                OutreachRecipient.id == recipient.id, OutreachRecipient.status == 'queued'
            ).values(status='sending', attempts=OutreachRecipient.attempts + 1, attempted_at=now())).rowcount
            _touch(batch_id)
            db.session.commit()
            if not claimed_row:
                pause = False
                continue
            attempt = OutreachAttempt(recipient_id=recipient.id,
                attempt_number=db.session.get(OutreachRecipient, recipient.id).attempts, status='sending')
            db.session.add(attempt)
            db.session.commit()
            attempt_id = attempt.id
            outcome = _process_recipient(batch_ctx, user_id, recipient, sender, quota)
            processed += 1
            if outcome == 'unconfirmed' and quota['sent'] is not None:
                quota['sent'] += 1
                quota['since_check'] += 1
            result_status = db.session.execute(select(OutreachRecipient.status).where(OutreachRecipient.id == recipient.id)).scalar()
            if result_status == 'failed' and OutreachAttempt.query.filter_by(recipient_id=recipient.id, status='unconfirmed').first():
                db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient.id).values(
                    status='unconfirmed', error='This attempt failed, but an earlier attempt is still unconfirmed. Check Sent mail before another resend.'))
            db.session.execute(update(OutreachAttempt).where(OutreachAttempt.id == attempt_id).values(status=result_status))
            svc.sequence_result(recipient.id)
            db.session.commit()
            if outcome in ('sent', 'unconfirmed', 'failed'): chunk_sent += 1
            pause = outcome != 'skipped'
            if outcome == 'stop':
                break
    finally:
        sender.close()
    _finish(batch_id, token)


def mark_stalled_unconfirmed(batch_id):
    """A worker died mid-send: that email may already be delivered, so never resend it automatically."""
    db.session.execute(update(OutreachRecipient).where(
        OutreachRecipient.batch_id == batch_id, OutreachRecipient.status == 'sending'
    ).values(status='unconfirmed',
             error='The app stopped while this was sending. Check your Sent mail before sending again.'))
    db.session.execute(update(OutreachAttempt).where(OutreachAttempt.recipient_id.in_(
        select(OutreachRecipient.id).where(OutreachRecipient.batch_id == batch_id)),
        OutreachAttempt.status == 'sending').values(status='unconfirmed'))


def retry_candidates(batch, include_unconfirmed):
    states = ['failed']
    if effective_status(batch) in ('stalled', 'paused'): states.append('queued')
    if include_unconfirmed: states.append('unconfirmed')
    return OutreachRecipient.query.filter(OutreachRecipient.batch_id == batch.id,
        OutreachRecipient.status.in_(states)).order_by(OutreachRecipient.position, OutreachRecipient.id).all()


def retry_digest(batch, candidates):
    import hashlib
    rows = [(row.id, row.status, row.attempts, svc.outreach_fingerprint(dict(
        to_email=row.email, subject=row.subject or '', body=row.body or '', pdf_files=json.loads(row.attachments or '[]')))) for row in candidates]
    return hashlib.sha256(json.dumps([batch.worker_token, batch.status, batch.paused_reason, rows]).encode()).hexdigest()


def _finish(batch_id, token):
    db.session.execute(update(OutreachBatch).where(
        OutreachBatch.id == batch_id, OutreachBatch.worker_token == token, OutreachBatch.status == 'sending'
    ).values(status='done', finished_at=now(), heartbeat_at=now(), lease_owner=None, lease_until=None))
    db.session.commit()


def skip_reason(batch, recipient, school):
    """Re-check the rules right before sending; the world may have changed since queueing."""
    if hasattr(svc,'agent_batch_guard'):
        reason=svc.agent_batch_guard(batch.id)
        if reason:return reason
    if hasattr(svc,'campaign_recipient_guard'):
        reason=svc.campaign_recipient_guard(recipient)
        if reason:return reason
    if batch.kind == 'test':
        user = db.session.get(svc.User, batch.user_id)
        return None if user and recipient.email == user.email and not svc.contact_is_blocked(recipient.email) else 'invalid_test_destination'
    if getattr(recipient, 'contact_id', None):
        if getattr(batch, 'campaign_id', None) and not svc.ContactOutreachLedger.query.filter_by(recipient_id=recipient.id).first():
            return 'superseded_review'
        contact = db.session.get(svc.Contact, recipient.contact_id)
        link = db.session.get(svc.SchoolContact, recipient.contact_link_id)
        if not contact or contact.email != recipient.email or svc.contact_is_blocked(contact.email):
            return 'unsubscribed'
        if not link or link.contact_id != contact.id or link.school_id != recipient.school_id or link.version != recipient.link_version or contact.version != recipient.contact_version:
            return 'contact_changed'
    if school is None:
        return 'school_deleted'
    if school.user_id != batch.user_id:
        return 'not_owner'
    saved_owner_version = getattr(recipient, 'ownership_version', None)
    if (saved_owner_version is None and school.ownership_version != 0) or (saved_owner_version is not None and saved_owner_version != school.ownership_version):
        return 'owner_changed'
    if not svc.valid_email(recipient.email):
        return 'missing_email'
    if svc.contact_is_blocked(recipient.email):
        return 'unsubscribed'
    if batch.kind == 'reply':
        original = db.session.get(svc.SentEmail, recipient.followup_of_email_id)
        return None if original and original.user_id == batch.user_id and original.school_email.casefold() == recipient.email.casefold() else 'conversation_changed'
    if school.status in CLOSED_STAGES:
        return 'closed'
    if school.status in REPLIED_STAGES:
        return 'replied'
    unsubscribed, replied = db.session.execute(select(
        exists().where(svc.SchoolActivity.sales_school_id == school.id,
                       svc.SchoolActivity.kind.in_(SUPPRESSION_KINDS)),
        exists().where(svc.SentEmail.sales_school_id == school.id, svc.SentEmail.responded.is_(True)),
    )).one()
    if unsubscribed:
        return 'unsubscribed'
    if batch.kind == 'sequence':
        if not svc.mail_sync_status(batch.user_id)['ready']: return 'inbox_not_synced'
        return svc.sequence_send_guard(recipient.id)
    if batch.kind == 'followup':
        if not svc.mail_sync_status(batch.user_id)['ready']:
            return 'inbox_not_synced'
        original = db.session.get(svc.SentEmail, recipient.followup_of_email_id) if recipient.followup_of_email_id else None
        if original and original.sequence_managed: return 'sequence_managed'
        due_at = svc.followup_due_at(original) if original is not None else None
        if original and original.sent_at < now() - timedelta(days=svc.FOLLOWUP_MAX_AGE_DAYS):
            return 'not_due'
        if due_at is None or now() < due_at:
            return 'not_due'
        if original.responded:
            return 'replied'
    elif replied and getattr(batch, 'campaign_id', None) in (None, 'standard'):
        return 'replied'
    return None


QUOTA_RECHECK_EVERY = 10


def _under_daily_limit(user_id, quota, batch=None):
    """Count today's sends once, track our own sends locally, and re-query every few sends or near the limit."""
    limit = mailbox_limit()
    if batch is not None and getattr(batch, 'campaign_id', None) not in (None, 'standard'):
        campaign = db.session.get(svc.OutreachCampaign, batch.campaign_id)
        if campaign is None or campaign.archived: return False
        used = campaign_used(user_id, campaign.id, include_reservations=False)
        if used >= campaign.daily_limit: return False
    sent = quota['sent']
    if sent is None or quota['since_check'] >= QUOTA_RECHECK_EVERY or limit - sent <= QUOTA_RECHECK_EVERY:
        sent = quota['sent'] = sent_today(user_id)
        quota['since_check'] = 0
    return sent < limit


def _looks_like_quota(error):
    text = str(error).lower()
    return '5.4.5' in text or 'quota' in text or 'sending limit' in text or 'rate limit' in text


def _process_recipient(batch, user_id, recipient, sender, quota):
    """Send one recipient. Returns 'skipped', 'sent', 'failed', 'unconfirmed' or 'stop' (abort the whole batch).

    `batch` and `recipient` are plain value objects (id, kind, columns), not ORM rows.
    """
    recipient_id, batch_id = recipient.id, batch.id
    school = db.session.get(svc.SalesSchool, recipient.school_id) if recipient.school_id else None
    reason = skip_reason(batch, recipient, school)
    if reason is None and not _under_daily_limit(user_id, quota, batch):
        reason = 'daily_limit'
    if reason:
        db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient_id).values(
            status='skipped', error=reason))
        db.session.commit()
        return 'skipped'

    job = {'to_email': recipient.email, 'subject': recipient.subject or '', 'body': recipient.body or '',
           'pdf_files': json.loads(recipient.attachments or '[]')}
    original = None
    if batch.kind in ('followup', 'reply', 'sequence') and recipient.followup_of_email_id:
        original = db.session.get(svc.SentEmail, recipient.followup_of_email_id)
        latest = svc.SentMessage.query.filter_by(sent_email_id=original.id).order_by(
            svc.SentMessage.sent_at.desc(), svc.SentMessage.id.desc()).first() if original else None
        job['in_reply_to'] = latest.message_id if latest else None
        if batch.kind == 'sequence' and original:
            ids = [m.message_id for m in svc.SentMessage.query.filter_by(sent_email_id=original.id).order_by(svc.SentMessage.sent_at, svc.SentMessage.id) if m.message_id]
            job['references'] = ' '.join(dict.fromkeys(ids[-20:]))

    # Everything below talks to the mail provider and can take seconds: do it without holding a pooled connection.
    db.session.rollback()

    if sender.server is None:
        try:
            sender.connect()
        except Exception as exc:
            error = 'SMTP login failed: ' + clean_error(exc)
            db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient_id).values(
                status='failed', error=error))
            db.session.commit()
            _fail_remaining(batch_id, error)
            return 'stop'

    try:
        sender.send(job)
    except svc.AmbiguousDelivery as exc:
        db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient_id).values(
            status='unconfirmed', error=clean_error(exc)))
        db.session.execute(update(OutreachAttempt).where(OutreachAttempt.recipient_id == recipient_id,
            OutreachAttempt.status == 'sending').values(status='unconfirmed'))
        db.session.commit()
        sender.close()
        return 'unconfirmed'
    except Exception as exc:
        error = clean_error(exc)
        db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient_id).values(
            status='failed', error=error))
        db.session.commit()
        sender.reset()
        from .mail_feedback import hard_bounce
        if hard_bounce(exc):
            svc.record_mail_signal(recipient.email, 'hard_bounce', f'smtp:{recipient_id}:{uuid.uuid4()}',
                                   'SMTP rejected the recipient: 5.1.1', actor_id=user_id, batch_id=batch_id)
            db.session.commit()
            return 'stop'
        if _looks_like_quota(exc):
            _fail_remaining(batch_id, 'Mail provider sending limit reached: ' + error)
            return 'stop'
        return 'failed'

    for attempt in range(2):
        try:
            _record_success(batch, user_id, recipient, school, original, job)
            quota['since_check'] += 1
            if quota['sent'] is not None:
                quota['sent'] += 1
            return 'sent'
        except Exception:
            db.session.rollback()
            log.exception('Could not record a sent outreach email (recipient %s, attempt %s)', recipient_id, attempt + 1)
    db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient_id).values(
        status='unconfirmed', error='Sent, but not recorded. Check your Sent mail before sending again.'))
    db.session.execute(update(OutreachAttempt).where(OutreachAttempt.recipient_id == recipient_id,
        OutreachAttempt.status == 'sending').values(status='unconfirmed'))
    db.session.commit()
    return 'unconfirmed'


def _record_success(batch, user_id, recipient, school, original, job):
    if batch.kind == 'test':
        db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient.id).values(
            status='sent', sent_at=now(), error=None))
        _touch(batch.id)
        db.session.commit()
        return
    if batch.kind == 'sequence' and original is not None:
        original = db.session.get(svc.SentEmail, original.id)
        svc.record_outbound_message(original, job.get('message_id'), recipient.subject, 'sequence_followup')
        sent_email = original
    elif batch.kind == 'reply' and original is not None:
        original = db.session.get(svc.SentEmail, original.id)
        svc.record_outbound_message(original, job.get('message_id'), recipient.subject, 'reply')
        sent_email = original
    elif batch.kind == 'followup' and original is not None:
        original = db.session.get(svc.SentEmail, original.id)
        svc.mark_followup_sent(original)
        svc.record_outbound_message(original, job.get('message_id'), recipient.subject, 'followup')
        sent_email = original
    else:
        school = db.session.get(svc.SalesSchool, school.id)
        sent_email = svc.SentEmail(
            school_name=school.school_name, school_email=recipient.email, user_id=user_id,
            sales_school_id=school.id, responded=False, followup_sent=False)
        db.session.add(sent_email)
        svc.record_outbound_message(sent_email, job.get('message_id'), recipient.subject, 'outreach')
        svc.advance_school_stage(school)
    db.session.flush()
    db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient.id).values(
        sent_email_id=sent_email.id, status='sent', sent_at=now(), error=None))
    _touch(batch.id)
    db.session.commit()


def queue_batch(user, options, token=None):
    """Create one outreach batch for this user. Returns (payload, http_status, batch or None).

    Shared by the Outreach screen and the automatic follow-up job so both apply the same rules.
    """
    kind = options['kind']
    if not token:
        return dict(error='Review every message before sending.'), 409, None
    if kind == 'followup' and not svc.mail_sync_status(user.id)['ready']:
        return dict(error='Check your inbox before sending follow-ups', code='inbox_not_synced'), 409, None
    # Serialize this user's batch creation so two requests cannot both see a school as free.
    db.session.query(svc.User.id).filter(svc.User.id == user.id).with_for_update().first()
    rows = owned_rows(user, options['ids'])
    if rows is None:
        return dict(error='Send only to schools assigned to you'), 403, None

    accepted, skipped = [], []
    contact_entries = {row[0].id: (contact, step) for row, contact, step in svc.legacy_contact_entries(rows, kind, lock=True)}
    busy = in_flight_school_ids(row[0].id for row in rows)
    accepted_addresses = set()
    for row in rows:
        blockers = compute_blockers(kind, row, user.id, busy)
        contact, step = contact_entries[row[0].id]
        if contact is None or svc.contact_step_reserved(contact, step) or contact.email in accepted_addresses:
            blockers.append('campaign_already_contacted')
        if blockers:
            skipped.append((row, blockers[0]))
        else:
            accepted.append(row)
            accepted_addresses.add(contact.email)

    contents = {}
    for row in accepted:
        school, latest = row[0], row[1]
        try:
            contents[school.id] = build_content(
                kind, user, school, latest, options['subject'], options['body'], options['attachments'], options.get('template'), options.get('catalog_files'))
        except ValueError as exc:
            return dict(error=str(exc)), 400, None
    if token is not None:
        try:
            review = svc.outreach_review_signer().loads(token, max_age=900)
        except BadSignature:
            return dict(error='Your message review expired. Review the messages again.'), 409, None
        prints = review.get('fingerprints', {})
        if review.get('uid') != user.id or any(
                prints.get(f'{row[0].id}:{chosen_email(row[0], row[1], kind)}')
                != fingerprint(chosen_email(row[0], row[1], kind), contents[row[0].id])
                for row in accepted):
            return dict(error='A recipient or message changed. Review the messages again before sending.'), 409, None

    limits = limits_for(user)
    if accepted and limits['remaining'] <= 0:
        return dict(error='Daily sending limit reached', code='daily_limit', **limits), 429, None
    allowed = accepted[:limits['remaining']]
    skipped.extend((row, 'daily_limit') for row in accepted[limits['remaining']:])
    if not allowed:
        return dict(error='No eligible recipients', code='no_eligible_recipients',
                       skipped=[{'school_id': row[0].id, 'reason': reason} for row, reason in skipped]), 400, None

    batch = OutreachBatch(user_id=user.id, kind=kind, status='queued', subject=options['subject'],
                          campaign_id='standard',
                          attachments=bool(options['attachments'] or (options.get('template') or {}).get('attachment_id') or options.get('catalog_files')),
                          template_snapshot=json.dumps(options['template']) if options.get('template') else None,
                          worker_token=str(uuid.uuid4()))
    db.session.add(batch)
    db.session.flush()
    skip_by_id = {row[0].id: reason for row, reason in skipped}
    allowed_ids = {row[0].id for row in allowed}
    for position, row in enumerate(rows):
        school, latest = row[0], row[1]
        if school.id in allowed_ids:
            content = contents[school.id]
            contact, step = contact_entries[school.id]
            link = svc.SchoolContact.query.filter_by(school_id=school.id, contact_id=contact.id).one()
            recipient = OutreachRecipient(
                batch_id=batch.id, position=position, school_id=school.id, school_name=school.school_name,
                email=chosen_email(school, latest, kind), status='queued', subject=content['subject'],
                body=content['body'], attachments=json.dumps(content['pdf_files']), ownership_version=school.ownership_version,
                contact_id=contact.id, contact_link_id=link.id, contact_version=contact.version, link_version=link.version,
                followup_of_email_id=latest.id if kind == 'followup' and latest is not None else None)
            db.session.add(recipient)
            db.session.flush()
            svc.reserve_contact_step(contact, step, recipient)
        else:
            db.session.add(OutreachRecipient(
                batch_id=batch.id, position=position, school_id=school.id, school_name=school.school_name,
                email=chosen_email(school, latest, kind), status='skipped', error=skip_by_id[school.id]))
    db.session.commit()
    return dict(batch_id=batch.id, status='queued', total=len(rows),
                skipped=[{'school_id': row[0].id, 'reason': reason} for row, reason in skipped]), 202, batch


# ---------------------------------------------------------------------------
# Automatic follow-ups
# ---------------------------------------------------------------------------

AUTO_FOLLOWUP_LOCK_KEY = 864_002_031
SENDING_TIME_ZONE = 'America/New_York'


def auto_followups_enabled():
    return os.getenv('AUTO_FOLLOWUPS_ENABLED', 'true').strip().lower() != 'false'


def in_sending_hours(moment=None):
    """Weekdays 9am-5pm Eastern: schools read mail then, and nobody gets a 3am follow-up."""
    local = (moment or datetime.now(timezone.utc)).astimezone(pytz.timezone(SENDING_TIME_ZONE))
    return local.weekday() < 5 and 9 <= local.hour < 17


def due_followup_school_ids(user):
    S = svc.SalesSchool
    current = now()
    query, Latest, _agg = school_rows_query()
    rows = query.filter(
        S.user_id == user.id, Latest.id.isnot(None), Latest.responded.isnot(True),
        S.status.notin_(tuple(REPLIED_STAGES | CLOSED_STAGES)),
        Latest.user_id == S.user_id, followup_due_filter(Latest, current),
        Latest.sent_at >= current - timedelta(days=svc.FOLLOWUP_MAX_AGE_DAYS),
    ).with_entities(S.id).order_by(Latest.sent_at.asc(), S.id).limit(MAX_BATCH_SCHOOLS).all()
    return [school_id for (school_id,) in rows]


def _auto_followups_for(app, user):
    """Check replies first, then queue whatever is due. Returns the number queued."""
    status = None
    for _ in range(3):  # a large backlog can need several bounded passes
        status = svc.sync_user_mailbox(user)
        if status['ready']:
            break
    if not status or not status['ready']:
        return 0
    ids = due_followup_school_ids(user)
    if not ids:
        return 0
    payload, code, batch = queue_batch(user, {'ids': ids, 'kind': 'followup', 'subject': None,
                                              'body': None, 'attachments': None})
    if batch is None:
        db.session.rollback()
        if code not in (400, 429):  # nothing eligible or daily limit: normal, try again later
            log.warning('Automatic follow-ups not queued for user %s: %s', user.id, payload.get('error'))
        return 0
    start_worker(app, batch.id, batch.worker_token)
    return code == 202 and payload['total'] - len(payload['skipped']) or 0


def run_auto_followups(app, force_hours=False):
    """Review mode cannot manufacture a rep approval. Automatic campaigns come next."""
    return {'queued': 0, 'skipped': 'Review mode: approve follow-ups in Outreach'}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def register_outreach_routes(app, database, service):
    global svc, db, OutreachBatch, OutreachRecipient, OutreachAttempt
    svc, db = service, database
    if OutreachBatch is None:
        OutreachBatch, OutreachRecipient, OutreachAttempt = _build_models()
    service.OutreachBatch, service.OutreachRecipient = OutreachBatch, OutreachRecipient
    service.OutreachAttempt = OutreachAttempt
    from .contact_outreach import register_contact_outreach
    register_contact_outreach(app, db, service, __import__(__name__, fromlist=['']))
    from .mail_feedback import register_mail_feedback
    register_mail_feedback(app, db, service, __import__(__name__, fromlist=['']))
    from .sequences import register_sequences
    register_sequences(app, db, service, __import__(__name__, fromlist=['']))
    from .outreach_worker import register_worker
    register_worker(app, db, service, __import__(__name__, fromlist=['']))

    def page_args():
        try:
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 50))
        except (TypeError, ValueError):
            raise ValueError('page and per_page must be integers')
        if page < 1 or not 1 <= per_page <= 200:
            raise ValueError('Use page >= 1 and per_page between 1 and 200')
        return page, per_page

    svc.contact_outreach_paging = page_args

    @app.get('/api/outreach/recipients')
    @jwt_required()
    def outreach_recipients():
        if request.args.get('contact_mode') == '1':
            viewer = current_user()
            if not viewer: return jsonify(error='User not found'), 404
            return svc.contact_school_picker(viewer)
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        kind = request.args.get('kind', 'initial')
        if kind not in KINDS:
            return jsonify(error="kind must be 'initial', 'followup' or 'custom'"), 400
        try:
            page, per_page = page_args()
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        S = svc.SalesSchool
        query, Latest, email_agg = school_rows_query()
        if not user.admin or request.args.get('scope') == 'mine':
            query = query.filter(S.user_id == user.id)
        stage = (request.args.get('stage') or '').strip()
        if stage:
            query = query.filter(S.status == stage[:40])
        term = (request.args.get('q') or '').strip().lower()[:120]
        if term:
            query = query.filter(or_(*[
                func.lower(field).contains(term, autoescape=True)
                for field in (S.school_name, S.contact_name, S.email)]))
        current = now()
        if kind == 'initial':
            query = query.filter(email_agg.c.sid.is_(None))
            order = (S.school_name.asc(), S.id)
        elif kind == 'followup':
            query = query.filter(
                Latest.id.isnot(None), Latest.responded.isnot(True),
                Latest.user_id == S.user_id, followup_due_filter(Latest, current),
                Latest.sent_at >= current - timedelta(days=svc.FOLLOWUP_MAX_AGE_DAYS))
            order = (Latest.sent_at.asc(), S.id)
        else:
            order = (S.school_name.asc(), S.id)
        total = query.order_by(None).count()
        rows = query.order_by(*order).offset((page - 1) * per_page).limit(per_page).all()
        items = []
        busy = in_flight_school_ids(row[0].id for row in rows)
        for row in rows:
            school, latest, last_email_at, _responded, last_message_at = row[:5]
            last_contact = max([item for item in (last_email_at, last_message_at) if item], default=None)
            blockers = compute_blockers(kind, row, user.id, busy)
            items.append({
                'school_id': school.id, 'school_name': school.school_name,
                'email': chosen_email(school, latest, kind), 'contact_name': school.contact_name,
                'status': school.status, 'owner_id': school.user_id, 'owner_name': row[6],
                'last_contacted_at': iso(last_contact),
                'days_since_contact': (current - last_contact).days if last_contact else None,
                'followup_due_at': iso(svc.followup_due_at(latest)) if latest is not None else None,
                'followups_sent': svc.followup_stage(latest) if latest is not None else 0,
                'eligible': not blockers, 'blockers': blockers,
            })
        return jsonify(items=items, total=total, page=page, per_page=per_page)

    @app.get('/api/outreach/limits')
    @jwt_required()
    def outreach_limits():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        return jsonify(limits_for(user))

    @app.post('/api/outreach/batches')
    @jwt_required()
    def outreach_create_batch():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='Supply an outreach request'), 400
        options, error = parse_request_options(data, MAX_BATCH_SCHOOLS)
        if error:
            return error
        token = data.get('preview_token')
        if token is not None and not isinstance(token, str):
            return jsonify(error='Invalid preview token'), 400
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        if not user.email_password:
            return jsonify(error='Email settings not configured', code='no_mailbox'), 400
        if data.get('contact_mode') is True:
            payload, status, batch = svc.queue_contact_outreach(user, options, data)
        else:
            payload, status, batch = queue_batch(user, options, token)
        if batch is not None:
            start_worker(current_app._get_current_object(), batch.id, batch.worker_token)
        return jsonify(**payload), status

    @app.get('/api/outreach/batches/<int:batch_id>')
    @jwt_required()
    def outreach_get_batch(batch_id):
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        batch = accessible_batch(user, batch_id)
        if not batch:
            return jsonify(error='Batch not found'), 404
        recipients = db.session.query(OutreachRecipient).filter_by(batch_id=batch.id).order_by(
            OutreachRecipient.position, OutreachRecipient.id).all()
        return jsonify(batch_dict(batch, counts_for([batch.id])[batch.id], recipients))

    @app.get('/api/outreach/batches')
    @jwt_required()
    def outreach_list_batches():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        try:
            limit = int(request.args.get('limit', 10))
        except (TypeError, ValueError):
            return jsonify(error='limit must be an integer'), 400
        if not 1 <= limit <= 50:
            return jsonify(error='Use a limit between 1 and 50'), 400
        query = db.session.query(OutreachBatch)
        if not user.admin or request.args.get('scope') == 'mine':
            query = query.filter(OutreachBatch.user_id == user.id)
        batches = query.order_by(OutreachBatch.created_at.desc(), OutreachBatch.id.desc()).limit(limit).all()
        counts = counts_for([batch.id for batch in batches])
        return jsonify(items=[batch_dict(batch, counts[batch.id]) for batch in batches])

    @app.post('/api/outreach/batches/<int:batch_id>/cancel')
    @jwt_required()
    def outreach_cancel_batch(batch_id):
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        batch = accessible_batch(user, batch_id, lock=True)
        if not batch:
            return jsonify(error='Batch not found'), 404
        if batch.status == 'done':
            return jsonify(error='This batch has already finished'), 409
        if effective_status(batch) == 'stalled':
            mark_stalled_unconfirmed(batch.id)
        cancelled = db.session.execute(update(OutreachRecipient).where(
            OutreachRecipient.batch_id == batch.id, OutreachRecipient.status == 'queued'
        ).values(status='cancelled')).rowcount
        if batch.status != 'cancelled':
            batch.status, batch.finished_at = 'cancelled', now()
        db.session.commit()
        return jsonify(batch_id=batch.id, status='cancelled', cancelled=cancelled)

    @app.post('/api/outreach/batches/<int:batch_id>/retry')
    @jwt_required()
    def outreach_retry_batch(batch_id):
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        batch = accessible_batch(user, batch_id)
        if not batch:
            return jsonify(error='Batch not found'), 404
        if batch.user_id != user.id:
            return jsonify(error='Only the original sender can approve a resend'), 403
        # Match queue/feedback lock order: sender, schools, contacts, then batch.
        ids = db.session.execute(select(OutreachRecipient.school_id, OutreachRecipient.contact_id).where(
            OutreachRecipient.batch_id == batch_id)).all()
        db.session.query(svc.SalesSchool.id).filter(svc.SalesSchool.id.in_([r.school_id for r in ids if r.school_id])).order_by(svc.SalesSchool.id).with_for_update().all()
        db.session.query(svc.Contact.id).filter(svc.Contact.id.in_([r.contact_id for r in ids if r.contact_id])).order_by(svc.Contact.id).with_for_update().all()
        db.session.expire_all()
        batch = accessible_batch(user, batch_id, lock=True)
        state = effective_status(batch)
        if state in ('queued', 'sending'):
            return jsonify(error='This batch is still sending'), 409
        stalled = state == 'stalled'
        body = request.get_json(silent=True)
        if body is not None and not isinstance(body, dict): return jsonify(error='Supply a retry object'), 400
        include_unconfirmed = isinstance(body, dict) and body.get('include_unconfirmed') is True
        if stalled:
            mark_stalled_unconfirmed(batch.id)
        candidates = retry_candidates(batch, include_unconfirmed)
        if not candidates:
            db.session.commit()
            return jsonify(error='Nothing to retry', code='nothing_to_retry'), 409
        try:
            review = svc.outreach_review_signer().loads((body or {}).get('preview_token', ''), max_age=900)
            expected = dict(uid=user.id, retry=batch.id, include_unconfirmed=include_unconfirmed, hash=retry_digest(batch, candidates))
            if review != expected: raise ValueError('Changed')
        except (BadSignature, ValueError, TypeError):
            db.session.rollback()
            return jsonify(error='Review the remaining messages before retrying'), 409
        if not candidates:
            if stalled:
                batch.status, batch.finished_at = 'done', now()
            db.session.commit()
            return jsonify(error='Nothing to retry', code='nothing_to_retry'), 409
        owner = db.session.get(svc.User, batch.user_id)
        if not owner or not owner.email_password:
            return jsonify(error='Email settings not configured', code='no_mailbox'), 400
        contacts = [row.contact_id for row in candidates if row.contact_id]
        db.session.query(svc.Contact.id).filter(svc.Contact.id.in_(contacts)).order_by(svc.Contact.id).with_for_update().all()
        if OutreachRecipient.query.filter(OutreachRecipient.email.in_([row.email for row in candidates]),
                OutreachRecipient.batch_id != batch.id, OutreachRecipient.status.in_(('queued', 'sending'))).first():
            return jsonify(error='A contact is already sending in another batch. Review after it finishes.'), 409
        if (batch.kind == 'followup' or batch.paused_reason) and not svc.mail_sync_status(user.id)['ready']:
            return jsonify(error='Check replies before approving follow-ups'), 409
        limits = limits_for(owner)
        if limits['remaining'] <= 0:
            return jsonify(error='Daily sending limit reached', code='daily_limit', **limits), 429
        accepted, rest = candidates[:limits['remaining']], candidates[limits['remaining']:]
        not_retried = []
        for item in rest:
            not_retried.append({'school_id': item.school_id, 'reason': 'daily_limit'})
            if item.status == 'queued':
                item.status, item.error = 'skipped', 'daily_limit'
        for item in accepted:
            item.status, item.error = 'queued', None
        batch.status, batch.finished_at, batch.paused_reason = 'queued', None, None
        batch.worker_token, batch.heartbeat_at = str(uuid.uuid4()), now()
        db.session.commit()
        start_worker(current_app._get_current_object(), batch.id, batch.worker_token)
        return jsonify(batch_id=batch.id, status='queued', requeued=len(accepted), not_retried=not_retried), 202

    @app.post('/api/outreach/batches/<int:batch_id>/retry-preview')
    @jwt_required()
    def outreach_retry_preview(batch_id):
        user = current_user()
        batch = accessible_batch(user, batch_id) if user else None
        if not batch: return jsonify(error='Batch not found'), 404
        if batch.user_id != user.id: return jsonify(error='Only the original sender can approve a resend'), 403
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict): return jsonify(error='Supply a review object'), 400
        include = body.get('include_unconfirmed') is True
        if effective_status(batch) in ('queued', 'sending'):
            return jsonify(error='This batch is still sending'), 409
        if effective_status(batch) == 'stalled':
            mark_stalled_unconfirmed(batch.id)
            db.session.commit()
        rows = retry_candidates(batch, include)
        token = svc.outreach_review_signer().dumps(dict(uid=user.id, retry=batch.id,
            include_unconfirmed=include, hash=retry_digest(batch, rows)))
        return jsonify(preview_token=token, previews=[dict(id=row.id, school_id=row.school_id,
            school_name=row.school_name, email=row.email, subject=row.subject, body_text=row.body,
            status=row.status, attachments=json.loads(row.attachments or '[]')) for row in rows])
