"""Reviewed, contact-targeted outreach. No SMTP or scheduler lives here.

The canonical mailbox row is the cross-rep serialization lock. A unique ledger
key survives batches, retries and school reassignments. Reviews are single-use,
actor-bound database snapshots, not client assertions about what was displayed.
"""
import hashlib
import json
import uuid
from datetime import timedelta
from types import SimpleNamespace

from flask import jsonify, request, current_app
from flask_jwt_extended import jwt_required
from sqlalchemy import func, select

AUDIENCES = ('all', 'principal_ap', 'pta_pto', 'enrichment', 'trunk_or_treat')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def register_contact_outreach(app, db, svc, out):
    class Campaign(db.Model):
        __tablename__ = 'outreach_campaigns'
        id = db.Column(db.String(36), primary_key=True)
        name = db.Column(db.String(150), nullable=False)
        reason = db.Column(db.Text, nullable=False)
        daily_limit = db.Column(db.Integer, nullable=False, default=150)
        archived = db.Column(db.Boolean, nullable=False, default=False)
        created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
        created_at = db.Column(db.DateTime, nullable=False, default=out.now)

    class Review(db.Model):
        __tablename__ = 'outreach_contact_reviews'
        id = db.Column(db.String(36), primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        snapshot = db.Column(db.Text, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
        batch_id = db.Column(db.Integer, db.ForeignKey('outreach_batches.id'))

    class Ledger(db.Model):
        __tablename__ = 'outreach_contact_ledger'
        id = db.Column(db.Integer, primary_key=True)
        campaign_id = db.Column(db.String(36), nullable=False)
        contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'), nullable=False)
        step = db.Column(db.String(40), nullable=False)
        recipient_id = db.Column(db.Integer, db.ForeignKey('outreach_recipients.id'), nullable=False, unique=True)
        __table_args__ = (db.UniqueConstraint('campaign_id', 'contact_id', 'step', name='uq_campaign_contact_step'),)

    svc.OutreachCampaign, svc.ContactOutreachReview, svc.ContactOutreachLedger = Campaign, Review, Ledger

    def campaign(value):
        if value == 'standard':
            return dict(id='standard', name='Standard outreach', daily_limit=out.daily_limit())
        if not isinstance(value, str):
            raise ValueError('Choose a campaign')
        row = db.session.get(Campaign, value)
        if row is None or row.archived:
            raise ValueError('Campaign unavailable')
        return dict(id=row.id, name=row.name, daily_limit=row.daily_limit)

    def resolve(user, options, data, max_contacts=100):
        selected = out.owned_rows(user, options['ids'])
        if selected is None:
            raise PermissionError('Send only to schools assigned to you')
        audience = data.get('audience', 'all')
        if audience not in AUDIENCES:
            raise ValueError('Choose a valid contact audience')
        template = options.get('template')
        if template and template['audience'] not in ('general', audience):
            raise ValueError('Choose the audience matching this template')
        choices = data.get('contact_contexts', {})
        if not isinstance(choices, dict) or len(choices) > max_contacts:
            raise ValueError('Choose a school context for shared contacts')
        cam = campaign(data.get('campaign_id', 'standard'))
        schools = {row[0].id: row[0] for row in selected}
        pairs = db.session.query(svc.SchoolContact, svc.Contact).join(
            svc.Contact, svc.Contact.id == svc.SchoolContact.contact_id).filter(
            svc.SchoolContact.school_id.in_(schools)).order_by(svc.Contact.id, svc.SchoolContact.school_id).all()
        grouped = {}
        for link, contact in pairs:
            matches = audience == 'all' or (audience in json.loads(link.roles_json)) or (
                audience == 'trunk_or_treat' and 'trunk_or_treat' in json.loads(link.tags_json))
            if matches:
                grouped.setdefault(contact.id, []).append((link, contact))
        if len(grouped) > max_contacts:
            raise ValueError(f'Review at most {max_contacts} contact mailboxes. Select fewer schools.')
        addresses = [links[0][1].email for links in grouped.values()]
        originals = svc.SentEmail.query.filter(func.lower(func.trim(svc.SentEmail.school_email)).in_(addresses)).order_by(
            svc.SentEmail.sent_at.desc(), svc.SentEmail.id.desc()).all()
        latest_mine, history = {}, {}
        for original in originals:
            address = original.school_email.strip().casefold()
            history.setdefault(address, original)
            if original.user_id == user.id: latest_mine.setdefault(address, original)
        entries = Ledger.query.filter(Ledger.contact_id.in_(list(grouped)), Ledger.campaign_id == cam['id']).all()
        states = {r.id: r.status for r in out.OutreachRecipient.query.filter(
            out.OutreachRecipient.id.in_([entry.recipient_id for entry in entries])).all()}
        for (recipient_id,) in db.session.query(out.OutreachAttempt.recipient_id).filter(
            out.OutreachAttempt.recipient_id.in_(list(states)), out.OutreachAttempt.status == 'unconfirmed').distinct().all():
            states[recipient_id] = 'unconfirmed'
        ledger = {(entry.contact_id, entry.step): states[entry.recipient_id] for entry in entries}
        intro_ids = [entry.recipient_id for entry in entries if entry.step == 'intro']
        intro_originals = {r.contact_id: db.session.get(svc.SentEmail, r.sent_email_id) for r in
            out.OutreachRecipient.query.filter(out.OutreachRecipient.id.in_(intro_ids)).all() if r.sent_email_id}
        busy_addresses = {email for (email,) in db.session.query(out.OutreachRecipient.email).filter(
            func.lower(func.trim(out.OutreachRecipient.email)).in_(addresses), out.OutreachRecipient.status.in_(('queued', 'sending'))).all()}
        busy_addresses = {address.strip().casefold() for address in busy_addresses}
        result = []
        for contact_id, links in grouped.items():
            chosen = choices.get(str(contact_id))
            if chosen is not None and (type(chosen) is not int or chosen not in [link.school_id for link, _ in links]):
                raise ValueError('Invalid school context')
            contexts = [{'school_id': link.school_id, 'school_name': schools[link.school_id].school_name,
                         'contact_name': link.name} for link, _ in links]
            unresolved = len(links) > 1 and chosen is None
            link, contact = next(((l, c) for l, c in links if l.school_id == chosen), links[0])
            school = schools[link.school_id]
            latest = latest_mine.get(contact.email)
            if options['kind'] == 'followup' and cam['id'] != 'standard': latest = intro_originals.get(contact.id)
            blockers = []
            if unresolved: blockers.append('choose_school_context')
            if contact.do_not_contact: blockers.append('unsubscribed')
            if school.status in out.CLOSED_STAGES: blockers.append('closed')
            if school.status in out.REPLIED_STAGES or (latest and latest.responded and
                (options['kind'] == 'followup' or cam['id'] == 'standard')): blockers.append('replied')
            if not user.email_password: blockers.append('no_mailbox')
            if options['kind'] == 'followup':
                if latest and latest.sequence_managed: blockers.append('sequence_managed')
                due = svc.followup_due_at(latest) if latest else None
                if due is None or out.now() < due: blockers.append('not_due')
                if latest and latest.sent_at < out.now() - timedelta(days=svc.FOLLOWUP_MAX_AGE_DAYS):
                    blockers.append('not_due')
                step = 'followup-' + str(svc.followup_stage(latest) + 1) if latest else 'followup-1'
                prior = ledger.get((contact.id, 'intro')) == 'sent' or (cam['id'] == 'standard' and latest is not None)
                if not prior: blockers.append('no_campaign_intro')
                if latest and (latest.user_id != user.id or latest.sales_school_id != school.id):
                    blockers.append('conversation_context_changed')
            else:
                step = 'intro'  # "custom" is still an intro, never a duplicate escape hatch
                recent = history.get(contact.email)
                if recent and recent.sent_at >= out.now() - timedelta(days=out.RECENT_CONTACT_DAYS):
                    blockers.append('recently_contacted')
                if cam['id'] == 'standard' and recent: blockers.append('campaign_already_contacted')
            existing = ledger.get((contact.id, step))
            if existing and existing not in ('cancelled', 'failed', 'skipped'):
                blockers.append('campaign_already_contacted')
            if contact.email in busy_addresses: blockers.append('in_flight')
            # All merge values come from the selected school/contact association.
            shadow = SimpleNamespace(**{column.name: getattr(school, column.name) for column in school.__table__.columns})
            shadow.contact_name, shadow.email = link.name, contact.email
            shadow.get_all_emails = lambda address=contact.email: [address]
            content = out.build_content(options['kind'], user, shadow, latest, options['subject'], options['body'],
                                        options['attachments'], template, options.get('catalog_files'))
            plain, html = svc.render_body_parts(content['body'])
            signature = dict(contact_version=contact.version, link_version=link.version,
                             owner_version=school.ownership_version, content=out.fingerprint(contact.email, content))
            result.append(dict(contact_id=contact.id, contact_link_id=link.id, school_id=school.id,
                               school_name=school.school_name, contact_name=link.name, email=contact.email,
                               contexts=contexts, context_required=unresolved, step=step,
                               subject=content['subject'], body_text=plain, body_html=html,
                               body=content['body'],
                               attachments=content['attachment_names'], pdf_files=content['pdf_files'],
                               warnings=blockers, blockers=blockers, eligible=not blockers, signature=signature,
                               followup_of_email_id=latest.id if latest and options['kind'] == 'followup' else None))
        return result, cam

    def preview(user, options, data):
        try:
            rows, cam = resolve(user, options, data)
        except PermissionError as exc:
            return jsonify(error=str(exc)), 403
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        payload = dict(rows=rows, campaign=cam, kind=options['kind'],
                       request_hash=digest({key: value for key, value in data.items() if key != 'preview_token'}))
        review = Review(id=str(uuid.uuid4()), user_id=user.id, snapshot=json.dumps(payload), expires_at=out.now() + timedelta(minutes=15))
        db.session.add(review)
        db.session.commit()
        return jsonify(previews=rows, preview_token=review.id, campaign=cam,
                       remaining=min(out.limits_for(user)['remaining'], max(0, cam['daily_limit'] - out.campaign_used(user.id, cam['id']))),
                       unmatched_school_ids=[sid for sid in options['ids'] if sid not in {c['school_id'] for r in rows for c in r['contexts']}],
                       recipient_count=len(rows))

    def queue(user, options, data, agent_draft=None):
        # Lock sender quota before review, school ownership, and canonical contacts.
        db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        review = Review.query.filter_by(id=data.get('preview_token'), user_id=user.id).with_for_update().first()
        if review is None:
            return dict(error='Review all contact messages before sending'), 409, None
        if review.batch_id:
            batch = db.session.get(out.OutreachBatch, review.batch_id)
            return dict(batch_id=batch.id, status=out.effective_status(batch), repeated=True), 200, None
        if review.expires_at <= out.now():
            return dict(error='Your review expired. Review again.'), 409, None
        saved = json.loads(review.snapshot)
        if not all(key in saved for key in ('rows', 'campaign', 'kind', 'request_hash')):
            return dict(error='Review this contact outreach before sending'), 409, None
        if saved['request_hash'] != digest({key: value for key, value in data.items() if key != 'preview_token'}):
            return dict(error='The selection or message changed. Review again.'), 409, None
        db.session.query(svc.SalesSchool).filter(svc.SalesSchool.id.in_(options['ids'])).order_by(
            svc.SalesSchool.id).with_for_update().all()
        ids = sorted(row['contact_id'] for row in saved['rows'])
        db.session.execute(select(svc.Contact.id).where(svc.Contact.id.in_(ids)).order_by(svc.Contact.id).with_for_update()).all()
        try:
            rows, cam = resolve(user, options, data)
        except (PermissionError, ValueError) as exc:
            return dict(error=str(exc)), 409, None
        if digest(rows) != digest(saved['rows']) or cam != saved['campaign']:
            return dict(error='A contact, message or eligibility changed. Review again.'), 409, None
        if options['kind'] == 'followup' and not svc.mail_sync_status(user.id)['ready']:
            return dict(error='Check your inbox before sending follow-ups', code='inbox_not_synced'), 409, None
        eligible = [row for row in rows if row['eligible']]
        limits = out.limits_for(user)
        campaign_used = out.campaign_used(user.id, cam['id'])
        remaining = min(limits['remaining'], max(0, cam['daily_limit'] - campaign_used))
        if not eligible:
            return dict(error='No eligible contacts. Resolve the warnings before sending.'), 400, None
        if len(eligible) > remaining:
            return dict(error=f'Only {remaining} emails remain within your mailbox and campaign limits.', code='daily_limit'), 429, None
        batch = out.OutreachBatch(user_id=user.id, kind=options['kind'], status='queued', campaign_id=cam['id'],
                                  subject=options['subject'], worker_token=str(uuid.uuid4()),
                                  template_snapshot=json.dumps(options['template']) if options.get('template') else None)
        db.session.add(batch)
        db.session.flush()
        for index, row in enumerate(eligible):
            recipient = out.OutreachRecipient(batch_id=batch.id, position=index, school_id=row['school_id'],
                school_name=row['school_name'], email=row['email'], subject=row['subject'], body=row['body'],
                attachments=json.dumps(row['pdf_files']), ownership_version=row['signature']['owner_version'],
                contact_id=row['contact_id'], contact_link_id=row['contact_link_id'],
                contact_version=row['signature']['contact_version'], link_version=row['signature']['link_version'],
                followup_of_email_id=row['followup_of_email_id'], status='queued')
            db.session.add(recipient)
            db.session.flush()
            entry = Ledger.query.filter_by(campaign_id=cam['id'], contact_id=row['contact_id'], step=row['step']).first()
            if entry:
                entry.recipient_id = recipient.id  # only definitely-unsent rows can be re-reviewed
            else:
                db.session.add(Ledger(campaign_id=cam['id'], contact_id=row['contact_id'], step=row['step'], recipient_id=recipient.id))
        review.batch_id = batch.id
        if agent_draft is not None:
            agent_draft.batch_id=batch.id;agent_draft.status='queued';agent_draft.executed_at=out.now()
            svc.record_agent_outreach_event(agent_draft,'queued')
        db.session.commit()
        return dict(batch_id=batch.id, status='queued', total=len(eligible), skipped=[]), 202, batch

    svc.preview_contact_outreach, svc.queue_contact_outreach = preview, queue
    svc.resolve_campaign_contacts = resolve

    def school_picker(user):
        try: page, per_page = svc.contact_outreach_paging()
        except ValueError as exc: return jsonify(error=str(exc)), 400
        if request.args.get('kind', 'initial') not in out.KINDS: return jsonify(error='Invalid outreach kind'), 400
        query = svc.SalesSchool.query.filter_by(user_id=user.id)
        term, stage = request.args.get('q', '').strip()[:200], request.args.get('stage')
        if term:
            from sqlalchemy import or_
            matching_contacts = db.session.query(svc.SchoolContact.school_id).join(svc.Contact).filter(
                or_(svc.Contact.email.ilike('%' + term + '%'), svc.SchoolContact.name.ilike('%' + term + '%')))
            query = query.filter(or_(svc.SalesSchool.school_name.ilike('%' + term + '%'),
                                     svc.SalesSchool.email.ilike('%' + term + '%'), svc.SalesSchool.id.in_(matching_contacts)))
        if stage: query = query.filter(svc.SalesSchool.status == stage)
        if request.args.get('kind') == 'followup':
            from .crm import followup_due_filter
            due = db.session.query(svc.SentEmail.sales_school_id).filter(svc.SentEmail.user_id == user.id,
                svc.SentEmail.responded.isnot(True), followup_due_filter(svc.SentEmail, out.now()))
            query = query.filter(svc.SalesSchool.id.in_(due))
        total = query.count()
        schools = query.order_by(svc.SalesSchool.school_name, svc.SalesSchool.id).offset((page-1)*per_page).limit(per_page).all()
        links = db.session.query(svc.SchoolContact, svc.Contact).join(svc.Contact).filter(
            svc.SchoolContact.school_id.in_([s.id for s in schools])).all()
        from sqlalchemy import func
        dates = dict(db.session.query(svc.SentEmail.sales_school_id,
            func.max(func.coalesce(svc.SentMessage.sent_at, svc.SentEmail.sent_at))).outerjoin(svc.SentMessage).filter(
            svc.SentEmail.user_id == user.id, svc.SentEmail.sales_school_id.in_([s.id for s in schools])).group_by(svc.SentEmail.sales_school_id).all())
        grouped = {}
        for link, contact in links: grouped.setdefault(link.school_id, []).append(contact)
        items = []
        for school in schools:
            contacts = grouped.get(school.id, [])
            blockers = []
            if not contacts: blockers.append('missing_email')
            elif all(c.do_not_contact for c in contacts): blockers.append('unsubscribed')
            if school.status in out.CLOSED_STAGES: blockers.append('closed')
            if school.status in out.REPLIED_STAGES: blockers.append('replied')
            if not user.email_password: blockers.append('no_mailbox')
            items.append(dict(school_id=school.id, school_name=school.school_name, email=school.email,
                contact_name=school.contact_name, contact_count=len(contacts), status=school.status,
                owner_id=user.id, owner_name=user.name, last_contacted_at=out.iso(dates.get(school.id)),
                days_since_contact=(out.now()-dates[school.id]).days if dates.get(school.id) else None,
                followup_due_at=None, followups_sent=0, eligible=not blockers, blockers=blockers))
        return jsonify(items=items, total=total, page=page, per_page=per_page)

    svc.contact_school_picker = school_picker

    def legacy_entries(rows, kind, lock=False):
        addresses = [out.chosen_email(row[0], row[1], kind).casefold() for row in rows]
        query = svc.Contact.query.filter(svc.Contact.email.in_(addresses)).order_by(svc.Contact.id)
        if lock: query = query.with_for_update()
        contacts = {contact.email: contact for contact in query.all()}
        return [(row, contacts.get(address), 'intro' if kind != 'followup' else
                 'followup-' + str(svc.followup_stage(row[1]) + 1)) for row, address in zip(rows, addresses)]

    def already_reserved(contact, step):
        if out.OutreachRecipient.query.filter(func.lower(func.trim(out.OutreachRecipient.email)) == contact.email,
            out.OutreachRecipient.status.in_(('queued', 'sending'))).first(): return True
        if step == 'intro' and svc.SentEmail.query.filter(func.lower(func.trim(svc.SentEmail.school_email)) == contact.email).first(): return True
        entry = Ledger.query.filter_by(campaign_id='standard', contact_id=contact.id, step=step).first()
        if entry:
            if out.OutreachAttempt.query.filter_by(recipient_id=entry.recipient_id, status='unconfirmed').first(): return True
            return db.session.get(out.OutreachRecipient, entry.recipient_id).status not in ('cancelled', 'failed', 'skipped')
        return False

    def reserve(contact, step, recipient):
        entry = Ledger.query.filter_by(campaign_id='standard', contact_id=contact.id, step=step).first()
        if entry: entry.recipient_id = recipient.id
        else: db.session.add(Ledger(campaign_id='standard', contact_id=contact.id, step=step, recipient_id=recipient.id))

    svc.legacy_contact_entries, svc.contact_step_reserved, svc.reserve_contact_step = legacy_entries, already_reserved, reserve

    @app.get('/api/outreach/campaigns')
    @jwt_required()
    def campaigns():
        user = out.current_user()
        if user is None: return jsonify(error='User not found'), 404
        return jsonify(items=[campaign('standard')] + [dict(id=c.id, name=c.name, daily_limit=c.daily_limit)
                       for c in Campaign.query.filter_by(archived=False).order_by(Campaign.created_at).all()])

    def reply_content(user, data):
        if not isinstance(data, dict): raise ValueError('Supply a reply object')
        if type(data.get('email_id')) is not int:
            raise ValueError('Choose a conversation')
        original = svc.SentEmail.query.filter_by(id=data['email_id'], user_id=user.id).first()
        school = db.session.get(svc.SalesSchool, original.sales_school_id) if original else None
        if original is None or school is None or school.user_id != user.id:
            raise ValueError('Reply only to a conversation for a school assigned to you')
        if not out.valid_subject(data.get('subject')) or not out.valid_body(data.get('message')):
            raise ValueError('Enter a valid subject and reply')
        contact = svc.Contact.query.filter_by(email=original.school_email.strip().casefold()).first()
        link = svc.SchoolContact.query.filter_by(school_id=school.id, contact_id=contact.id).first() if contact else None
        if not contact or not link or svc.contact_is_blocked(contact.email):
            raise ValueError('This conversation contact is unavailable or suppressed')
        return original, school, contact, link, dict(email=contact.email, subject=data['subject'], body_text=data['message'],
            ownership_version=school.ownership_version, contact_version=contact.version, link_version=link.version,
            school_id=school.id, original_id=original.id)

    @app.post('/api/outreach/reply-preview')
    @jwt_required()
    def reply_preview():
        user, data = out.current_user(), request.get_json(silent=True) or {}
        if user is None: return jsonify(error='User not found'), 404
        try: original, school, contact, link, content = reply_content(user, data)
        except ValueError as exc: return jsonify(error=str(exc)), 400
        review = Review(id=str(uuid.uuid4()), user_id=user.id,
            snapshot=json.dumps(dict(reply=content, request_hash=digest(data))), expires_at=out.now() + timedelta(minutes=15))
        db.session.add(review)
        db.session.commit()
        return jsonify(**content, preview_token=review.id)

    @app.post('/api/outreach/reply-send')
    @jwt_required()
    def reply_send(agent_draft=None):
        user, data = out.current_user(), request.get_json(silent=True) or {}
        if user is None: return jsonify(error='User not found'), 404
        if not isinstance(data, dict) or not isinstance(data.get('preview_token'), str):
            return jsonify(error='Review your reply before sending'), 409
        db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        review = Review.query.filter_by(id=data.get('preview_token'), user_id=user.id).with_for_update().first()
        if not review: return jsonify(error='Review your reply before sending'), 409
        if review.batch_id: return jsonify(batch_id=review.batch_id, repeated=True), 200
        if review.expires_at <= out.now(): return jsonify(error='Review expired'), 409
        try: original, school, contact, link, content = reply_content(user, data)
        except ValueError as exc: return jsonify(error=str(exc)), 409
        db.session.query(svc.SalesSchool.id).filter_by(id=school.id).with_for_update().first()
        db.session.query(svc.Contact.id).filter_by(id=contact.id).with_for_update().first()
        db.session.expire_all()
        try: original, school, contact, link, content = reply_content(user, data)
        except ValueError as exc: return jsonify(error=str(exc)), 409
        saved = json.loads(review.snapshot)
        if saved != dict(reply=content, request_hash=digest({k: v for k, v in data.items() if k != 'preview_token'})):
            return jsonify(error='Conversation or reply changed. Review again.'), 409
        if not user.email_password: return jsonify(error='Connect your mailbox'), 400
        if out.limits_for(user)['remaining'] < 1: return jsonify(error='Daily sending limit reached'), 429
        batch = out.OutreachBatch(user_id=user.id, kind='reply', status='queued', worker_token=str(uuid.uuid4()))
        db.session.add(batch)
        db.session.flush()
        db.session.add(out.OutreachRecipient(batch_id=batch.id, position=0, school_id=school.id, school_name=school.school_name,
            email=contact.email, subject=content['subject'], body=content['body_text'], attachments='[]',
            contact_id=contact.id, contact_link_id=link.id, contact_version=contact.version, link_version=link.version,
            ownership_version=school.ownership_version, followup_of_email_id=original.id, status='queued'))
        review.batch_id = batch.id
        if agent_draft is not None:
            agent_draft.batch_id=batch.id;agent_draft.status='queued';agent_draft.executed_at=svc.utc_now()
            svc.record_agent_outreach_event(agent_draft,'queued')
        db.session.commit()
        out.start_worker(current_app._get_current_object(), batch.id, batch.worker_token)
        return jsonify(batch_id=batch.id, status='queued'), 202

    @app.post('/api/outreach/campaigns')
    @jwt_required()
    def create_campaign():
        user = out.current_user()
        if user is None or not user.admin: return jsonify(error='Admin access required'), 403
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict): return jsonify(error='Supply a campaign object'), 400
        name, reason, cap = data.get('name'), data.get('reason'), data.get('daily_limit', out.daily_limit())
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 150 or not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 1000 or type(cap) is not int or not 1 <= cap <= out.daily_limit():
            return jsonify(error='Supply a name, a reason for a distinct campaign, and a daily cap within the platform limit'), 400
        row = Campaign(id=str(uuid.uuid4()), name=name.strip(), reason=reason.strip(), daily_limit=cap, created_by=user.id)
        db.session.add(row)
        db.session.commit()
        return jsonify(id=row.id, name=row.name, daily_limit=row.daily_limit), 201

    @app.post('/api/outreach/test-preview')
    @jwt_required()
    def test_preview():
        user = out.current_user()
        data = request.get_json(silent=True)
        options, error = out.parse_request_options(data, 1)
        if error: return error
        if user is None: return jsonify(error='User not found'), 404
        rows = out.owned_rows(user, options['ids'])
        if not rows: return jsonify(error='Choose one of your schools as the example'), 403
        school = rows[0][0]
        try:
            content = out.build_content(options['kind'], user, school, rows[0][1], options['subject'], options['body'],
                                        options['attachments'], options.get('template'), options.get('catalog_files'))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        proof = Review(id=str(uuid.uuid4()), user_id=user.id, expires_at=out.now() + timedelta(minutes=15),
            snapshot=json.dumps(dict(test=True, request_hash=digest(data), school=school.id, hash=out.fingerprint(user.email, content))))
        db.session.add(proof)
        db.session.commit()
        return jsonify(email=user.email, subject=content['subject'], body_text=content['body'], attachments=content['attachment_names'], preview_token=proof.id)

    @app.post('/api/outreach/test-send')
    @jwt_required()
    def test_send():
        user = out.current_user()
        data = request.get_json(silent=True)
        options, error = out.parse_request_options(data, 1)
        if error: return error
        if user is None or not user.email_password: return jsonify(error='Connect your mailbox'), 400
        if not isinstance(data.get('preview_token'), str): return jsonify(error='Review the test message again'), 409
        db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        review = Review.query.filter_by(id=data.get('preview_token'), user_id=user.id).with_for_update().first()
        if not review or review.expires_at <= out.now(): return jsonify(error='Review the test message again'), 409
        if review.batch_id: return jsonify(batch_id=review.batch_id, repeated=True), 200
        rows = out.owned_rows(user, options['ids'])
        if not rows: return jsonify(error='Choose one of your schools'), 403
        try:
            content = out.build_content(options['kind'], user, rows[0][0], rows[0][1], options['subject'], options['body'],
                                        options['attachments'], options.get('template'), options.get('catalog_files'))
            proof = json.loads(review.snapshot)
            if proof != dict(test=True, request_hash=digest({key: value for key, value in data.items() if key != 'preview_token'}), school=rows[0][0].id, hash=out.fingerprint(user.email, content)):
                raise ValueError('Message changed')
        except Exception:
            return jsonify(error='Review the test message again'), 409
        if svc.contact_is_blocked(user.email): return jsonify(error='Your destination is suppressed'), 409
        if out.limits_for(user)['remaining'] < 1: return jsonify(error='Daily sending limit reached'), 429
        # A test is audited in batch recipients but never creates school history/enrollment.
        batch = out.OutreachBatch(user_id=user.id, kind='test', status='queued', worker_token=str(uuid.uuid4()))
        db.session.add(batch)
        db.session.flush()
        db.session.add(out.OutreachRecipient(batch_id=batch.id, position=0, school_name='Test to myself', email=user.email,
            status='queued', subject=content['subject'], body=content['body'], attachments=json.dumps(content['pdf_files'])))
        review.batch_id = batch.id
        db.session.commit()
        out.start_worker(current_app._get_current_object(), batch.id, batch.worker_token)
        return jsonify(batch_id=batch.id, status='queued'), 202
