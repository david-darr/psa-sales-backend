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

import pytz

from flask import current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from itsdangerous import BadSignature
from sqlalchemy import case, exists, func, or_, select, text, update
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
        sent_email_id = db.Column(db.Integer, db.ForeignKey('sent_emails.id', ondelete='SET NULL'))
        sent_at = db.Column(db.DateTime)
        subject = db.Column(db.Text)
        body = db.Column(db.Text)
        attachments = db.Column(db.Text)
        followup_of_email_id = db.Column(db.Integer, db.ForeignKey('sent_emails.id', ondelete='SET NULL'))

    return _OutreachBatch, _OutreachRecipient


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
    return now().replace(hour=0, minute=0, second=0, microsecond=0)


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
    return outreach + other


def reserved_count(user_id):
    """Recipients already promised to live batches, so two batches cannot overshoot the limit."""
    return db.session.query(func.count(OutreachRecipient.id)).join(
        OutreachBatch, OutreachBatch.id == OutreachRecipient.batch_id).filter(
        OutreachBatch.user_id == user_id,
        OutreachBatch.status.in_(('queued', 'sending')),
        OutreachBatch.heartbeat_at >= now() - STALL_AFTER,
        OutreachRecipient.status.in_(('queued', 'sending'))).scalar() or 0


def limits_for(user):
    limit = daily_limit()
    sent = sent_today(user.id)
    reserved = reserved_count(user.id)
    return {
        'daily_limit': limit,
        'sent_today': sent,
        'remaining': max(0, limit - sent - reserved),
        'reserved': reserved,
        'resets_at': iso(day_start() + timedelta(days=1)),
        'mailbox_connected': bool(user.email_password),
    }


def effective_status(batch):
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
    suppressed = exists().where(SA.sales_school_id == S.id, SA.kind.in_(SUPPRESSION_KINDS)).correlate(S)
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
        return (latest.school_email or '').strip()
    for item in school.get_all_emails():
        if svc.valid_email(item):
            return item.strip()
    return (school.email or '').strip()


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


def build_content(kind, user, school, latest, subject, body, attachments):
    """Render one recipient's message with the existing templates; never duplicates them."""
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
    return {'subject': rendered_subject, 'body': text, 'pdf_files': pdf_files}


def fingerprint(email_address, content):
    return svc.outreach_fingerprint({
        'to_email': email_address, 'subject': content['subject'],
        'body': content['body'], 'pdf_files': content['pdf_files']})


def parse_request_options(data, max_schools):
    """Validate the fields shared by preview and batch creation. Returns (options, error_response)."""
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
    unique = list(dict.fromkeys(ids))
    return {'ids': unique, 'kind': kind, 'subject': subject, 'body': body, 'attachments': attachments}, None


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
    rows = owned_rows(user, options['ids'])
    if rows is None:
        return jsonify(error='Send only to schools assigned to you'), 403
    kind = options['kind']
    previews, fingerprints = [], {}
    busy = in_flight_school_ids(row[0].id for row in rows)
    for row in rows:
        school, latest = row[0], row[1]
        blockers = compute_blockers(kind, row, user.id, busy)
        content = build_content(kind, user, school, latest, options['subject'], options['body'], options['attachments'])
        address = chosen_email(school, latest, kind)
        plain, html_body = svc.render_body_parts(content['body'])
        warnings = [name for name in blockers if name in PREVIEW_WARNINGS]
        if not (school.contact_name or '').strip():
            warnings.append('empty_greeting')
        fingerprints[f'{school.id}:{address}'] = fingerprint(address, content)
        previews.append({
            'school_id': school.id, 'school_name': school.school_name, 'email': address,
            'subject': content['subject'], 'body_html': html_body, 'body_text': plain,
            'warnings': warnings, 'attachments': content['pdf_files'],
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
    }
    if recipients is not None:
        data['recipients'] = [{
            'school_id': item.school_id, 'school_name': item.school_name, 'email': item.email,
            'status': item.status, 'error': item.error, 'sent_at': iso(item.sent_at),
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
    thread = threading.Thread(target=run_batch, args=(app, batch_id, token),
                              name=f'outreach-batch-{batch_id}', daemon=True)
    thread.start()
    return thread


def run_batch(app, batch_id, token, delay=None):
    """Thread entry point. Never raises; every failure is recorded on the recipient or batch."""
    with app.app_context():
        try:
            _process_batch(batch_id, token, send_delay() if delay is None else delay)
        except Exception:
            db.session.rollback()
            log.exception('Outreach batch %s worker crashed', batch_id)
        finally:
            db.session.remove()


def _touch(batch_id):
    db.session.execute(update(OutreachBatch).where(OutreachBatch.id == batch_id).values(heartbeat_at=now()))


def _fail_remaining(batch_id, error):
    db.session.execute(update(OutreachRecipient).where(
        OutreachRecipient.batch_id == batch_id, OutreachRecipient.status == 'queued'
    ).values(status='failed', error=clean_error(error)))
    db.session.commit()


def _process_batch(batch_id, token, delay):
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
    batch_ctx = SimpleNamespace(id=batch.id, kind=batch.kind, user_id=batch.user_id)
    user_id = user.id
    quota = {'sent': None, 'since_check': 0}
    pause = False
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
            recipient = db.session.execute(select(
                OutreachRecipient.id, OutreachRecipient.school_id, OutreachRecipient.email,
                OutreachRecipient.subject, OutreachRecipient.body, OutreachRecipient.attachments,
                OutreachRecipient.followup_of_email_id,
            ).where(OutreachRecipient.batch_id == batch_id, OutreachRecipient.status == 'queued').order_by(
                OutreachRecipient.position, OutreachRecipient.id).limit(1)).one_or_none()
            if recipient is None:
                break
            claimed_row = db.session.execute(update(OutreachRecipient).where(
                OutreachRecipient.id == recipient.id, OutreachRecipient.status == 'queued'
            ).values(status='sending', attempts=OutreachRecipient.attempts + 1)).rowcount
            _touch(batch_id)
            db.session.commit()
            if not claimed_row:
                pause = False
                continue
            outcome = _process_recipient(batch_ctx, user_id, recipient, sender, quota)
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


def _finish(batch_id, token):
    db.session.execute(update(OutreachBatch).where(
        OutreachBatch.id == batch_id, OutreachBatch.worker_token == token, OutreachBatch.status == 'sending'
    ).values(status='done', finished_at=now(), heartbeat_at=now()))
    db.session.commit()


def skip_reason(batch, recipient, school):
    """Re-check the rules right before sending; the world may have changed since queueing."""
    if school is None:
        return 'school_deleted'
    if school.user_id != batch.user_id:
        return 'not_owner'
    if not svc.valid_email(recipient.email):
        return 'missing_email'
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
    if batch.kind == 'followup':
        original = db.session.get(svc.SentEmail, recipient.followup_of_email_id) if recipient.followup_of_email_id else None
        due_at = svc.followup_due_at(original) if original is not None else None
        if due_at is None or now() < due_at:
            return 'not_due'
        if original.responded:
            return 'replied'
    elif replied:
        return 'replied'
    return None


QUOTA_RECHECK_EVERY = 10


def _under_daily_limit(user_id, quota):
    """Count today's sends once, track our own sends locally, and re-query every few sends or near the limit."""
    limit = daily_limit()
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
    if reason is None and not _under_daily_limit(user_id, quota):
        reason = 'daily_limit'
    if reason:
        db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient_id).values(
            status='skipped', error=reason))
        db.session.commit()
        return 'skipped'

    job = {'to_email': recipient.email, 'subject': recipient.subject or '', 'body': recipient.body or '',
           'pdf_files': json.loads(recipient.attachments or '[]')}
    original = None
    if batch.kind == 'followup' and recipient.followup_of_email_id:
        original = db.session.get(svc.SentEmail, recipient.followup_of_email_id)
        latest = svc.SentMessage.query.filter_by(sent_email_id=original.id).order_by(
            svc.SentMessage.sent_at.desc()).first() if original else None
        job['in_reply_to'] = latest.message_id if latest else None

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
        db.session.commit()
        sender.close()
        return 'unconfirmed'
    except Exception as exc:
        error = clean_error(exc)
        db.session.execute(update(OutreachRecipient).where(OutreachRecipient.id == recipient_id).values(
            status='failed', error=error))
        db.session.commit()
        sender.reset()
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
    db.session.commit()
    return 'unconfirmed'


def _record_success(batch, user_id, recipient, school, original, job):
    if batch.kind == 'followup' and original is not None:
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
    if kind == 'followup' and not svc.mail_sync_status(user.id)['ready']:
        return dict(error='Check your inbox before sending follow-ups', code='inbox_not_synced'), 409, None
    # Serialize this user's batch creation so two requests cannot both see a school as free.
    db.session.query(svc.User.id).filter(svc.User.id == user.id).with_for_update().first()
    rows = owned_rows(user, options['ids'])
    if rows is None:
        return dict(error='Send only to schools assigned to you'), 403, None

    accepted, skipped = [], []
    busy = in_flight_school_ids(row[0].id for row in rows)
    for row in rows:
        blockers = compute_blockers(kind, row, user.id, busy)
        if blockers:
            skipped.append((row, blockers[0]))
        else:
            accepted.append(row)

    contents = {}
    for row in accepted:
        school, latest = row[0], row[1]
        contents[school.id] = build_content(
            kind, user, school, latest, options['subject'], options['body'], options['attachments'])
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
                          attachments=bool(options['attachments']), worker_token=str(uuid.uuid4()))
    db.session.add(batch)
    db.session.flush()
    skip_by_id = {row[0].id: reason for row, reason in skipped}
    allowed_ids = {row[0].id for row in allowed}
    for position, row in enumerate(rows):
        school, latest = row[0], row[1]
        if school.id in allowed_ids:
            content = contents[school.id]
            db.session.add(OutreachRecipient(
                batch_id=batch.id, position=position, school_id=school.id, school_name=school.school_name,
                email=chosen_email(school, latest, kind), status='queued', subject=content['subject'],
                body=content['body'], attachments=json.dumps(content['pdf_files']),
                followup_of_email_id=latest.id if kind == 'followup' and latest is not None else None))
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
    """Queue due day-3 and day-7 follow-ups for every rep with a connected mailbox.

    Safe to call from every web process: a Postgres advisory lock lets one run at a time.
    """
    with app.app_context():
        if not auto_followups_enabled() or (not force_hours and not in_sending_hours()):
            return {'queued': 0, 'skipped': 'outside sending hours or disabled'}
        lock = None
        if db.engine.dialect.name == 'postgresql':
            lock = db.engine.connect()
            if not lock.execute(text('SELECT pg_try_advisory_lock(:k)'), {'k': AUTO_FOLLOWUP_LOCK_KEY}).scalar():
                lock.close()
                return {'queued': 0, 'skipped': 'another process is running follow-ups'}
        queued = 0
        try:
            users = svc.User.query.filter(svc.User.email_password.isnot(None)).order_by(svc.User.id).all()
            for user in users:
                try:
                    queued += _auto_followups_for(app, user)
                except Exception:
                    db.session.rollback()
                    log.exception('Automatic follow-ups failed for user %s', user.id)
        finally:
            if lock is not None:
                lock.execute(text('SELECT pg_advisory_unlock(:k)'), {'k': AUTO_FOLLOWUP_LOCK_KEY})
                lock.close()
            db.session.remove()
        return {'queued': queued}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def register_outreach_routes(app, database, service):
    global svc, db, OutreachBatch, OutreachRecipient
    svc, db = service, database
    if OutreachBatch is None:
        OutreachBatch, OutreachRecipient = _build_models()
    service.OutreachBatch, service.OutreachRecipient = OutreachBatch, OutreachRecipient

    def page_args():
        try:
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 50))
        except (TypeError, ValueError):
            raise ValueError('page and per_page must be integers')
        if page < 1 or not 1 <= per_page <= 200:
            raise ValueError('Use page >= 1 and per_page between 1 and 200')
        return page, per_page

    @app.get('/api/outreach/recipients')
    @jwt_required()
    def outreach_recipients():
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
        batch = accessible_batch(user, batch_id, lock=True)
        if not batch:
            return jsonify(error='Batch not found'), 404
        state = effective_status(batch)
        if state in ('queued', 'sending'):
            return jsonify(error='This batch is still sending'), 409
        stalled = state == 'stalled'
        body = request.get_json(silent=True)
        include_unconfirmed = isinstance(body, dict) and body.get('include_unconfirmed') is True
        if stalled:
            mark_stalled_unconfirmed(batch.id)
        retryable = ['failed'] + (['queued'] if stalled else []) + (['unconfirmed'] if include_unconfirmed else [])
        candidates = db.session.query(OutreachRecipient).filter(
            OutreachRecipient.batch_id == batch.id, OutreachRecipient.status.in_(retryable)
        ).order_by(OutreachRecipient.position, OutreachRecipient.id).all()
        if not candidates:
            if stalled:
                batch.status, batch.finished_at = 'done', now()
            db.session.commit()
            return jsonify(error='Nothing to retry', code='nothing_to_retry'), 409
        owner = db.session.get(svc.User, batch.user_id)
        if not owner or not owner.email_password:
            return jsonify(error='Email settings not configured', code='no_mailbox'), 400
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
        batch.status, batch.finished_at = 'queued', None
        batch.worker_token, batch.heartbeat_at = str(uuid.uuid4()), now()
        db.session.commit()
        start_worker(current_app._get_current_object(), batch.id, batch.worker_token)
        return jsonify(batch_id=batch.id, status='queued', requeued=len(accepted), not_retried=not_retried), 202
