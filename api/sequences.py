"""Versioned, explicitly enrolled follow-up sequences. No in-process timers.

The dedicated worker calls schedule_due; SMTP uses the common outreach ledger,
quota, suppression and attempt audit. A manual intro never enrolls itself.
"""
import json
import uuid
from datetime import date, datetime, time, timedelta, timezone
from types import SimpleNamespace
from zoneinfo import ZoneInfo

from flask import jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import and_, event, exists, inspect, or_, select, update
from sqlalchemy.orm import aliased
from .contact_outreach import digest, AUDIENCES
from .template_library import render_copy

EASTERN = ZoneInfo('America/New_York')
STOP_STAGES = ('replied', 'meeting', 'partner', 'former', 'not_interested')


def utc(value):
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def next_window(value, start=9, end=17):
    """UTC naive -> next allowed weekday instant, preserving wall-clock time."""
    local = value.replace(tzinfo=timezone.utc).astimezone(EASTERN)
    if local.hour >= end:
        local = datetime.combine(local.date() + timedelta(days=1), time(start), EASTERN)
    if local.hour < start:
        local = datetime.combine(local.date(), time(start), EASTERN)
    while local.weekday() > 4: local += timedelta(days=1)
    return utc(local)


def nominal_due(intro, days, start=9, end=17):
    local = intro.replace(tzinfo=timezone.utc).astimezone(EASTERN) + timedelta(days=days)
    return next_window(utc(local), start, end)


def register_sequences(app, db, svc, out):
    class Sequence(db.Model):
        __tablename__ = 'mail_sequences'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(150), nullable=False)
        revision = db.Column(db.Integer, nullable=False, default=1)
        definition = db.Column(db.Text, nullable=False)
        archived = db.Column(db.Boolean, nullable=False, default=False)

    class Version(db.Model):
        __tablename__ = 'mail_sequence_versions'
        id = db.Column(db.Integer, primary_key=True)
        sequence_id = db.Column(db.Integer, db.ForeignKey('mail_sequences.id'), nullable=False)
        revision = db.Column(db.Integer, nullable=False)
        definition = db.Column(db.Text, nullable=False)
        actor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        created_at = db.Column(db.DateTime, nullable=False, default=out.now)
        __table_args__ = (db.UniqueConstraint('sequence_id', 'revision'),)

    class Enrollment(db.Model):
        __tablename__ = 'mail_sequence_enrollments'
        id = db.Column(db.Integer, primary_key=True)
        original_id = db.Column(db.Integer, db.ForeignKey('sent_emails.id', ondelete='SET NULL'))
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id', ondelete='SET NULL'))
        contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'), nullable=False)
        sequence_id = db.Column(db.Integer, db.ForeignKey('mail_sequences.id'), nullable=False)
        revision = db.Column(db.Integer, nullable=False)
        generation = db.Column(db.Integer, nullable=False, default=1)
        campaign_id = db.Column(db.String(36), nullable=False)
        mode = db.Column(db.String(12), nullable=False, default='review')
        status = db.Column(db.String(12), nullable=False, default='active')
        reason = db.Column(db.Text)
        snapshot = db.Column(db.Text, nullable=False)
        starts_at = db.Column(db.DateTime, nullable=False)
        ends_at = db.Column(db.DateTime, nullable=False)
        approved_at = db.Column(db.DateTime, nullable=False, default=out.now)
        __table_args__ = (db.UniqueConstraint('original_id', 'generation'),)

    class Step(db.Model):
        __tablename__ = 'mail_sequence_steps'
        id = db.Column(db.Integer, primary_key=True)
        enrollment_id = db.Column(db.Integer, db.ForeignKey('mail_sequence_enrollments.id'), nullable=False)
        number = db.Column(db.Integer, nullable=False)
        due_at = db.Column(db.DateTime, nullable=False)
        status = db.Column(db.String(12), nullable=False, default='waiting')
        content = db.Column(db.Text, nullable=False)
        recipient_id = db.Column(db.Integer, db.ForeignKey('outreach_recipients.id'), unique=True)
        approved_until = db.Column(db.DateTime)
        lease_token = db.Column(db.String(36))
        lease_until = db.Column(db.DateTime)
        sent_at = db.Column(db.DateTime)
        __table_args__ = (db.UniqueConstraint('enrollment_id', 'number'),)

    class Review(db.Model):
        __tablename__ = 'mail_sequence_reviews'
        id = db.Column(db.String(36), primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        payload = db.Column(db.Text, nullable=False)
        created_at = db.Column(db.DateTime, nullable=False, default=out.now)
        expires_at = db.Column(db.DateTime, nullable=False)
        result = db.Column(db.Text)

    svc.MailSequence, svc.MailSequenceVersion = Sequence, Version
    svc.SequenceEnrollment, svc.SequenceStep, svc.SequenceReview = Enrollment, Step, Review

    def lock_enrollment(eid):
        enrollment=db.session.get(Enrollment,eid)
        if not enrollment:return None
        uid,sid,cid=enrollment.user_id,enrollment.school_id,enrollment.contact_id
        db.session.query(svc.User.id).filter_by(id=uid).with_for_update().first()
        if sid:db.session.query(svc.SalesSchool.id).filter_by(id=sid).with_for_update().first()
        db.session.query(svc.Contact.id).filter_by(id=cid).with_for_update().first()
        return Enrollment.query.filter_by(id=eid).populate_existing().with_for_update().first()

    def stop(enrollment, reason):
        enrollment=lock_enrollment(enrollment.id)
        if not enrollment:return
        if enrollment.status != 'active': return
        enrollment.status, enrollment.reason = 'paused', reason
        steps = Step.query.filter(Step.enrollment_id == enrollment.id, Step.status.in_(('waiting', 'checking', 'queued'))).all()
        for step in steps:
            step.status, step.approved_until = 'stopped', None
            if step.recipient_id:
                db.session.execute(update(out.OutreachRecipient).where(out.OutreachRecipient.id == step.recipient_id,
                    out.OutreachRecipient.status == 'queued').values(status='cancelled', error=reason))

    @event.listens_for(svc.SalesSchool, 'after_update')
    def remember_stop(_mapper, connection, school):
        # Persist the stop in the same transaction as the stage change. Resetting
        # the stage before the next worker tick cannot resurrect an approval.
        if inspect(school).attrs.status.history.has_changes() and school.status in STOP_STAGES:
            connection.execute(update(Enrollment).where(Enrollment.school_id == school.id,
                Enrollment.status == 'active').values(status='paused', reason='School stage changed to ' + school.status))
            connection.execute(update(Step).where(Step.enrollment_id.in_(select(Enrollment.id).where(
                Enrollment.school_id == school.id)), Step.status.in_(('waiting', 'checking', 'queued'))).values(
                status='stopped', approved_until=None))

    def definition(data):
        if not isinstance(data, dict): raise ValueError('Supply sequence settings')
        name, audience = data.get('name'), data.get('audience', 'all')
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 150 or audience not in AUDIENCES:
            raise ValueError('Choose a sequence name and audience')
        start, end = data.get('start_hour', 9), data.get('end_hour', 17)
        if type(start) is not int or type(end) is not int or not 6 <= start < end <= 20:
            raise ValueError('Use a weekday Eastern business window between 6am and 8pm')
        steps = data.get('steps')
        if not isinstance(steps, list) or not 1 <= len(steps) <= 3: raise ValueError('Choose one to three follow-up templates')
        checked, prior = [], 0
        for index, item in enumerate(steps, 1):
            if not isinstance(item, dict): raise ValueError('Supply a template and day for each step')
            day = item.get('day', [4, 10, 17][index-1])
            if type(day) is not int or not prior < day <= 90: raise ValueError('Days must increase, from 1 to 90 after the intro')
            template = svc.resolve_mail_template(dict(kind='followup', template_id=item.get('template_id'), template_revision=item.get('template_revision')))
            if template is None or template['step'] != index or template['audience'] not in ('general', audience):
                raise ValueError('Choose matching audience templates in follow-up step order')
            checked.append(dict(number=index, day=day, template=template)); prior = day
        return dict(name=name.strip(), audience=audience, start_hour=start, end_hour=end, time_zone='America/New_York', steps=checked)

    def guard(enrollment, step=None, check_window=True):
        moment = out.now()
        if hasattr(svc,'campaign_enrollment_block'):
            blocked=svc.campaign_enrollment_block(enrollment.id)
            if blocked:return blocked
        if enrollment.status != 'active': return enrollment.reason or 'Sequence paused or cancelled'
        sequence = db.session.get(Sequence, enrollment.sequence_id)
        if not sequence or sequence.archived or sequence.revision != enrollment.revision: return 'Sequence settings changed; prepare a new approval'
        if out.now() >= enrollment.ends_at: return 'Authorization expired'
        snap = json.loads(enrollment.snapshot)
        original = db.session.get(svc.SentEmail, enrollment.original_id) if enrollment.original_id else None
        school = db.session.get(svc.SalesSchool, enrollment.school_id) if enrollment.school_id else None
        contact = db.session.get(svc.Contact, enrollment.contact_id)
        link = db.session.get(svc.SchoolContact, snap['link_id'])
        if not original or original.responded: return 'Conversation replied or unavailable'
        if not school or school.user_id != enrollment.user_id or school.ownership_version != snap['ownership_version']: return 'School owner changed'
        if school.status in STOP_STAGES: return 'School is no longer eligible'
        if not contact or contact.do_not_contact: return 'Contact suppressed'
        if not link or link.school_id != school.id or link.contact_id != contact.id or link.version != snap['link_version'] or contact.version != snap['contact_version']: return 'Contact details changed'
        if original.school_email.strip().casefold() != contact.email: return 'Original recipient changed'
        cfg = snap['definition']
        for item in cfg['steps']:
            template = db.session.get(svc.MailTemplate, item['template']['id'])
            if not template or template.archived or template.revision != item['template']['revision']: return 'A sequence template changed or was archived'
        if step:
            if step.status not in ('waiting', 'checking', 'queued'): return 'Sequence step is no longer pending'
            if Step.query.filter(Step.enrollment_id == enrollment.id, Step.number < step.number,
                Step.status != 'sent').first(): return 'Previous sequence step is not complete'
            if enrollment.mode == 'review' and (not step.approved_until or step.approved_until <= out.now()): return 'Step approval required or expired'
            if check_window and (moment < max(step.due_at, enrollment.starts_at) or next_window(moment, cfg['start_hour'], cfg['end_hour']) != moment): return 'Outside the approved sending window'
            content = json.loads(step.content)
            try:
                fingerprint = svc.outreach_fingerprint(dict(to_email=contact.email, subject=content['subject'], body=content['body'], pdf_files=content['pdf_files']))
            except (ValueError, OSError): return 'Attachment unavailable'
            if fingerprint != content['fingerprint']: return 'Attachment bytes changed'
        return None

    def prepare(user, data, anchor):
        if not isinstance(data, dict): raise ValueError('Supply enrollment settings')
        if not user.email_password: raise ValueError('Connect your mailbox before enrolling')
        ids = data.get('original_ids')
        if not isinstance(ids, list) or not 1 <= len(ids) <= 100 or any(type(i) is not int or i < 1 for i in ids): raise ValueError('Select 1–100 original conversations')
        sequence = db.session.get(Sequence, data.get('sequence_id')) if type(data.get('sequence_id')) is int else None
        if not sequence or sequence.archived or sequence.revision != data.get('revision'): raise ValueError('Sequence changed; choose its current version')
        cfg = json.loads(sequence.definition)
        for item in cfg['steps']:
            current = db.session.get(svc.MailTemplate, item['template']['id'])
            if not current or current.archived or current.revision != item['template']['revision']:
                raise ValueError('A pinned template changed. Update the sequence and review again.')
        mode = data.get('mode', 'review')
        if mode not in ('review', 'automatic'): raise ValueError('Choose review or automatic mode')
        local_today = anchor.replace(tzinfo=timezone.utc).astimezone(EASTERN).date()
        try:
            starts = date.fromisoformat(data['start_date']); ends = date.fromisoformat(data['end_date'])
        except (ValueError, KeyError, TypeError): raise ValueError('Choose start and end dates')
        if not local_today <= starts <= ends <= local_today + timedelta(days=90): raise ValueError('Authorize a date range within the next 90 days')
        start_at, end_at = utc(datetime.combine(starts, time(cfg['start_hour']), EASTERN)), utc(datetime.combine(ends, time(cfg['end_hour']), EASTERN))
        if end_at <= anchor: raise ValueError('Choose an authorization end date in the future')
        rows, seen = [], set()
        for oid in sorted(set(ids)):
            original = svc.SentEmail.query.filter_by(id=oid, user_id=user.id).first()
            school = db.session.get(svc.SalesSchool, original.sales_school_id) if original and original.sales_school_id else None
            if not original or not school or school.user_id != user.id or original.responded or school.status in STOP_STAGES: raise ValueError('Choose your own unanswered, school-linked conversations')
            contact = svc.Contact.query.filter_by(email=original.school_email.strip().casefold()).first()
            link = svc.SchoolContact.query.filter_by(school_id=school.id, contact_id=contact.id).first() if contact else None
            if not contact or contact.do_not_contact or not link: raise ValueError('A selected contact is unavailable or suppressed')
            audience = cfg['audience']
            if audience != 'all' and audience not in json.loads(link.roles_json) and not (audience == 'trunk_or_treat' and audience in json.loads(link.tags_json)): raise ValueError('A selected contact does not match the sequence audience')
            messages = svc.SentMessage.query.filter_by(sent_email_id=oid).order_by(svc.SentMessage.sent_at, svc.SentMessage.id).all()
            if not messages or not messages[0].message_id: raise ValueError('A stored original Message-ID is required for safe threading')
            recipient = out.OutreachRecipient.query.filter_by(sent_email_id=oid, status='sent').order_by(out.OutreachRecipient.id).first()
            source_batch = db.session.get(out.OutreachBatch, recipient.batch_id) if recipient else None
            campaign = source_batch.campaign_id if source_batch and source_batch.campaign_id else 'standard'
            if (campaign, contact.id) in seen: raise ValueError('Choose one original conversation per campaign and mailbox')
            seen.add((campaign, contact.id))
            prior = Enrollment.query.filter_by(original_id=oid).order_by(Enrollment.generation.desc()).first()
            replace = data.get('replace_existing') is True
            if prior and not replace: raise ValueError('Already enrolled. Explicitly review a replacement to change it.')
            if original.sent_at < anchor - timedelta(days=90): raise ValueError('Do not enroll conversations older than 90 days')
            shadow = SimpleNamespace(school_name=school.school_name, contact_name=link.name)
            sent_numbers = {s.number for s in Step.query.filter_by(enrollment_id=prior.id, status='sent').all()} if prior else set()
            legacy_count = svc.followup_stage(original)
            sent_numbers.update(range(1, legacy_count + 1))
            content_rows = []
            for item in cfg['steps']:
                template = item['template']
                subject, body = render_copy(template['subject'], template['body'], shadow, user)
                files = ['template-asset:' + asset['id'] for asset in template.get('attachments', [])]
                fp = svc.outreach_fingerprint(dict(to_email=contact.email, subject=subject, body=body, pdf_files=files))
                due = next_window(max(nominal_due(original.sent_at, item['day'], cfg['start_hour'], cfg['end_hour']), start_at, anchor), cfg['start_hour'], cfg['end_hour'])
                content_rows.append(dict(number=item['number'], day=item['day'], subject=subject, body=body,
                    pdf_files=files, attachments=[a['name'] for a in template.get('attachments', [])], fingerprint=fp,
                    due_at=out.iso(due), already_sent=item['number'] in sent_numbers))
            if all(row['already_sent'] for row in content_rows): raise ValueError('All selected sequence steps were already sent')
            if any(datetime.fromisoformat(row['due_at'].rstrip('Z')) >= end_at for row in content_rows if not row['already_sent']):
                raise ValueError('The end date must cover every remaining step')
            rows.append(dict(original_id=oid, school_id=school.id, school_name=school.school_name, email=contact.email,
                contact_id=contact.id, link_id=link.id, link_version=link.version, contact_version=contact.version,
                ownership_version=school.ownership_version, campaign_id=campaign, prior_id=prior.id if prior else None,
                generation=(prior.generation + 1) if prior else 1, steps=content_rows))
        return dict(sequence_id=sequence.id, revision=sequence.revision, definition=cfg, mode=mode, rows=rows,
                    starts_at=out.iso(start_at), ends_at=out.iso(end_at), request_hash=digest(data))

    def serial(enrollment):
        snap = json.loads(enrollment.snapshot)
        return dict(id=enrollment.id, school_name=snap['school_name'], email=snap['email'], sequence_name=snap['definition']['name'],
            revision=enrollment.revision, mode=enrollment.mode, status=enrollment.status, reason=enrollment.reason,
            starts_at=out.iso(enrollment.starts_at), ends_at=out.iso(enrollment.ends_at), user_id=enrollment.user_id,
            steps=[{**json.loads(s.content), 'id':s.id, 'number':s.number, 'due_at':out.iso(s.due_at),
                'status':s.status, 'sent_at':out.iso(s.sent_at), 'approved_until':out.iso(s.approved_until)}
                for s in Step.query.filter_by(enrollment_id=enrollment.id).order_by(Step.number)])

    @app.route('/api/outreach/sequences', methods=['GET', 'POST'])
    @jwt_required()
    def sequences():
        user = out.current_user()
        if not user: return jsonify(error='User not found'), 404
        if request.method == 'GET': return jsonify(items=[dict(id=s.id, revision=s.revision, archived=s.archived, **json.loads(s.definition)) for s in Sequence.query.order_by(Sequence.id)])
        if not user.admin: return jsonify(error='Admin access required'), 403
        try: cfg = definition(request.get_json(silent=True))
        except ValueError as exc: return jsonify(error=str(exc)), 400
        row = Sequence(name=cfg['name'], definition=json.dumps(cfg)); db.session.add(row); db.session.flush()
        db.session.add(Version(sequence_id=row.id, revision=1, definition=row.definition, actor_id=user.id)); db.session.commit()
        return jsonify(id=row.id, revision=1, **cfg), 201

    @app.put('/api/outreach/sequences/<int:sid>')
    @jwt_required()
    def sequence_edit(sid):
        user, data = out.current_user(), request.get_json(silent=True)
        if not user or not user.admin: return jsonify(error='Admin access required'), 403
        try: cfg = definition(data)
        except ValueError as exc: return jsonify(error=str(exc)), 400
        row = Sequence.query.filter_by(id=sid).with_for_update().first()
        if not row or row.revision != data.get('revision'): return jsonify(error='Sequence changed'), 409
        if type(data.get('archived', False)) is not bool: return jsonify(error='Invalid archive flag'), 400
        row.revision += 1; row.name = cfg['name']; row.definition = json.dumps(cfg); row.archived = data.get('archived', False)
        db.session.add(Version(sequence_id=row.id, revision=row.revision, definition=row.definition, actor_id=user.id))
        for enrollment in Enrollment.query.filter_by(sequence_id=sid, status='active').order_by(Enrollment.user_id,Enrollment.id).all(): stop(enrollment, 'Sequence settings changed; prepare a new approval')
        db.session.commit(); return jsonify(id=row.id, revision=row.revision, archived=row.archived, **cfg)

    @app.get('/api/outreach/sequence-originals')
    @jwt_required()
    def originals():
        user = out.current_user()
        if not user: return jsonify(error='User not found'), 404
        try:
            page, size = int(request.args.get('page',1)), int(request.args.get('per_page',50))
            if page<1 or not 1<=size<=100: raise ValueError()
        except ValueError: return jsonify(error='Use page >= 1 and page size 1–100'),400
        query = svc.SentEmail.query.join(svc.SalesSchool).filter(svc.SentEmail.user_id==user.id,
            svc.SentEmail.responded.isnot(True),svc.SalesSchool.user_id==user.id, svc.SalesSchool.status.notin_(STOP_STAGES),
            svc.SentEmail.sent_at >= out.now()-timedelta(days=90))
        term=request.args.get('q','').strip()[:200]
        if term: query=query.filter(or_(svc.SentEmail.school_name.ilike('%'+term+'%'),svc.SentEmail.school_email.ilike('%'+term+'%')))
        total=query.count()
        rows=query.order_by(svc.SentEmail.sent_at.desc(),svc.SentEmail.id.desc()).offset((page-1)*size).limit(size).all()
        return jsonify(items=[dict(id=r.id, school_name=r.school_name, email=r.school_email, sent_at=out.iso(r.sent_at),
            already_managed=r.sequence_managed, legacy_followups=svc.followup_stage(r)) for r in rows],total=total,page=page,per_page=size)

    @app.get('/api/outreach/sequences/<int:sid>/versions')
    @jwt_required()
    def versions(sid):
        user = out.current_user()
        if not user or not user.admin: return jsonify(error='Admin access required'), 403
        return jsonify(items=[dict(revision=v.revision, actor_id=v.actor_id, created_at=out.iso(v.created_at),
            **json.loads(v.definition)) for v in Version.query.filter_by(sequence_id=sid).order_by(Version.revision.desc())])

    @app.post('/api/outreach/sequence-enrollments/preview')
    @jwt_required()
    def enrollment_preview():
        user, data = out.current_user(), request.get_json(silent=True)
        if not user: return jsonify(error='User not found'), 404
        anchor = out.now()
        try: payload = prepare(user, data, anchor)
        except ValueError as exc: return jsonify(error=str(exc)), 400
        review = Review(id=str(uuid.uuid4()), user_id=user.id, payload=json.dumps(payload), created_at=anchor, expires_at=anchor+timedelta(minutes=15))
        db.session.add(review); db.session.commit()
        return jsonify(review_id=review.id, **payload)

    @app.post('/api/outreach/sequence-enrollments/commit')
    @jwt_required()
    def enrollment_commit():
        user, data = out.current_user(), request.get_json(silent=True)
        if not user: return jsonify(error='User not found'), 404
        if not isinstance(data, dict) or not isinstance(data.get('review_id'), str): return jsonify(error='Review the enrollment first'), 409
        db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        review = Review.query.filter_by(id=data['review_id'], user_id=user.id).with_for_update().first()
        if not review or review.expires_at <= out.now(): return jsonify(error='Review expired or unavailable'), 409
        if review.result: return jsonify(**json.loads(review.result))
        old = json.loads(review.payload)
        if old.get('mode') == 'automatic' and data.get('confirm') != 'AUTHORIZE_AUTOMATIC_SEQUENCE': return jsonify(error='Explicit automatic-send authorization required'), 409
        request_data = data.get('settings')
        school_ids = [r['school_id'] for r in old['rows']]
        db.session.query(svc.SalesSchool.id).filter(svc.SalesSchool.id.in_(school_ids)).order_by(svc.SalesSchool.id).with_for_update().all()
        db.session.query(svc.Contact.id).filter(svc.Contact.id.in_([r['contact_id'] for r in old['rows']])).order_by(svc.Contact.id).with_for_update().all()
        try: current = prepare(user, request_data, review.created_at)
        except ValueError as exc: return jsonify(error=str(exc)), 409
        if digest(current) != digest(old): return jsonify(error='Enrollment, template or contact changed. Review again.'), 409
        created = []
        for row in current['rows']:
            prior = db.session.get(Enrollment, row['prior_id']) if row['prior_id'] else None
            if prior:
                pending_ids = select(Step.recipient_id).where(Step.enrollment_id == prior.id)
                if out.OutreachRecipient.query.filter(out.OutreachRecipient.id.in_(pending_ids), out.OutreachRecipient.status == 'sending').first(): return jsonify(error='Wait for the current message to finish before replacing'), 409
                stop(prior, 'Replaced by an explicitly reviewed enrollment')
            enrollment = Enrollment(original_id=row['original_id'], user_id=user.id, school_id=row['school_id'], contact_id=row['contact_id'],
                sequence_id=current['sequence_id'], revision=current['revision'], generation=row['generation'], campaign_id=row['campaign_id'],
                mode=current['mode'], snapshot=json.dumps({**row, 'definition':current['definition']}),
                starts_at=datetime.fromisoformat(current['starts_at'].rstrip('Z')), ends_at=datetime.fromisoformat(current['ends_at'].rstrip('Z')))
            db.session.add(enrollment); db.session.flush()
            for item in row['steps']:
                db.session.add(Step(enrollment_id=enrollment.id, number=item['number'],
                    due_at=datetime.fromisoformat(item['due_at'].rstrip('Z')), status='sent' if item['already_sent'] else 'waiting', content=json.dumps(item)))
            db.session.get(svc.SentEmail, row['original_id']).sequence_managed = True
            created.append(enrollment.id)
        review.result = json.dumps(dict(enrollment_ids=created)); db.session.commit()
        return jsonify(enrollment_ids=created), 201

    @app.get('/api/outreach/sequence-enrollments')
    @jwt_required()
    def enrollments():
        user = out.current_user()
        if not user: return jsonify(error='User not found'), 404
        try:
            page=max(1,int(request.args.get('page',1)));size=min(100,max(1,int(request.args.get('per_page',50))))
        except (TypeError,ValueError): return jsonify(error='Invalid pagination'),400
        query=Enrollment.query.filter_by(user_id=user.id)
        return jsonify(items=[serial(e) for e in query.order_by(Enrollment.id.desc()).offset((page-1)*size).limit(size)],total=query.count(),page=page)

    @app.post('/api/outreach/sequence-enrollments/<int:eid>/cancel')
    @jwt_required()
    def cancel(eid):
        user = out.current_user()
        if user: db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        enrollment = Enrollment.query.filter_by(id=eid, user_id=user.id).first() if user else None
        if not enrollment: return jsonify(error='Enrollment not found'), 404
        stop(enrollment, 'Authorization revoked by sender'); enrollment.status = 'cancelled'
        db.session.commit(); return jsonify(id=eid, status='cancelled')

    @app.post('/api/outreach/sequence-steps/<int:sid>/preview')
    @jwt_required()
    def step_preview(sid):
        user = out.current_user(); step = db.session.get(Step, sid)
        enrollment = db.session.get(Enrollment, step.enrollment_id) if step else None
        if not user or not enrollment or enrollment.user_id != user.id: return jsonify(error='Step not found'), 404
        reason = guard(enrollment, check_window=False)
        if reason or step.status != 'waiting': return jsonify(error=reason or 'Step is not waiting'), 409
        content = json.loads(step.content)
        token = svc.outreach_review_signer().dumps(dict(uid=user.id, sequence_step=sid, hash=digest([content, enrollment.snapshot, step.status])))
        return jsonify(**content, email=json.loads(enrollment.snapshot)['email'], preview_token=token)

    @app.post('/api/outreach/sequence-steps/<int:sid>/approve')
    @jwt_required()
    def step_approve(sid):
        user, data = out.current_user(), request.get_json(silent=True) or {}
        if not isinstance(data, dict): return jsonify(error='Supply a step approval'), 400
        step = Step.query.filter_by(id=sid).with_for_update().first()
        enrollment = db.session.get(Enrollment, step.enrollment_id) if step else None
        if not user or not enrollment or enrollment.user_id != user.id: return jsonify(error='Step not found'), 404
        try:
            proof = svc.outreach_review_signer().loads(data.get('preview_token',''), max_age=900)
            if proof != dict(uid=user.id, sequence_step=sid, hash=digest([json.loads(step.content), enrollment.snapshot, step.status])): raise ValueError()
        except Exception: return jsonify(error='Review this step again'), 409
        reason = guard(enrollment, check_window=False)
        if reason or step.status != 'waiting' or out.now() < step.due_at: return jsonify(error=reason or 'This step is not due'), 409
        step.approved_until = out.now()+timedelta(minutes=15); db.session.commit()
        return jsonify(id=sid, approved_until=out.iso(step.approved_until))

    def send_guard(recipient_id):
        step = Step.query.filter_by(recipient_id=recipient_id).first()
        if not step: return 'Sequence step missing'
        enrollment = db.session.get(Enrollment, step.enrollment_id)
        return guard(enrollment, step)

    def result(recipient_id):
        step = Step.query.filter_by(recipient_id=recipient_id).first()
        if not step or step.status != 'queued': return
        enrollment=lock_enrollment(step.enrollment_id)
        step=Step.query.filter_by(id=step.id).populate_existing().with_for_update().first()
        if step.status!='queued':return
        recipient = db.session.get(out.OutreachRecipient, recipient_id)
        if recipient.status == 'sent':
            step.status, step.sent_at = 'sent', recipient.sent_at
            cfg = json.loads(enrollment.snapshot)['definition']
            following = Step.query.filter_by(enrollment_id=enrollment.id, number=step.number+1).first()
            if following:
                # Overdue steps do not catch up in a single burst: at least one
                # local calendar day and the next business window after a send.
                local = recipient.sent_at.replace(tzinfo=timezone.utc).astimezone(EASTERN) + timedelta(days=1)
                following.due_at = max(following.due_at, next_window(utc(local), cfg['start_hour'], cfg['end_hour']))
            elif enrollment.status == 'active': enrollment.status = 'done'
        elif recipient.status in ('failed', 'skipped', 'unconfirmed', 'cancelled'):
            step.status = 'unconfirmed' if recipient.status == 'unconfirmed' else 'stopped'
            stop(enrollment, recipient.error or 'Sequence delivery needs review')

    def pause_recipient(recipient_id, reason):
        step = Step.query.filter_by(recipient_id=recipient_id).first()
        if step: stop(db.session.get(Enrollment, step.enrollment_id), reason)

    def dispatch_time(batch_id):
        step=Step.query.join(out.OutreachRecipient,out.OutreachRecipient.id==Step.recipient_id).filter(out.OutreachRecipient.batch_id==batch_id).first()
        if not step:return None
        enrollment=db.session.get(Enrollment,step.enrollment_id)
        if guard(enrollment):return None
        cfg=json.loads(enrollment.snapshot)['definition']
        allowed=next_window(max(out.now(),step.due_at,enrollment.starts_at),cfg['start_hour'],cfg['end_hour'])
        if allowed>out.now():step.due_at=allowed
        return allowed

    def schedule_due(limit=5):
        # Reconcile durable recipient outcomes before advancing any sequence.
        for step in Step.query.filter_by(status='queued').order_by(Step.id).limit(100).all():
            enrollment=db.session.get(Enrollment,step.enrollment_id)
            if hasattr(svc,'campaign_enrollment_block') and svc.campaign_enrollment_block(enrollment.id):continue
            reason=guard(enrollment)
            if reason:stop(enrollment,reason)
            else:result(step.recipient_id)
            db.session.commit()
        db.session.commit()
        earlier=aliased(Step)
        candidates = db.session.query(Step.id).join(Enrollment).filter(Step.status == 'waiting',
            Enrollment.status == 'active', Step.due_at <= out.now(),
            or_(Enrollment.mode=='automatic', Step.approved_until>out.now()),
            ~exists().where(earlier.enrollment_id==Step.enrollment_id,earlier.number<Step.number,earlier.status!='sent')
            ).order_by(Step.due_at, Step.id).limit(100).all()
        queued = 0
        for (sid,) in candidates:
            if queued >= limit: break
            step = db.session.get(Step, sid); enrollment = db.session.get(Enrollment, step.enrollment_id)
            if hasattr(svc,'campaign_enrollment_block') and svc.campaign_enrollment_block(enrollment.id):continue
            reason = guard(enrollment)
            if reason:
                stop(enrollment, reason); db.session.commit(); continue
            if enrollment.mode == 'review' and (not step.approved_until or step.approved_until <= out.now()): continue
            cfg = json.loads(enrollment.snapshot)['definition']
            moment = out.now()
            next_allowed=next_window(max(moment,enrollment.starts_at),cfg['start_hour'],cfg['end_hour'])
            if next_allowed != moment:
                step.due_at=max(step.due_at,next_allowed);db.session.commit();continue
            if Step.query.filter(Step.enrollment_id==enrollment.id, Step.number < step.number, Step.status!='sent').first(): continue
            token = str(uuid.uuid4())
            claimed = db.session.execute(update(Step).where(Step.id==sid, Step.status=='waiting').values(
                status='checking', lease_token=token, lease_until=out.now()+timedelta(minutes=5))).rowcount
            db.session.commit()
            if not claimed: continue
            try: ready = svc.sync_user_mailbox(db.session.get(svc.User, enrollment.user_id)).get('ready', False)
            except Exception: db.session.rollback(); ready = False
            # Use queue's lock order. Network calls above hold no enrollment lock.
            uid, school_id, contact_id = enrollment.user_id, enrollment.school_id, enrollment.contact_id
            db.session.rollback()
            db.session.query(svc.User.id).filter_by(id=uid).with_for_update().first()
            db.session.query(svc.SalesSchool.id).filter_by(id=school_id).with_for_update().first()
            db.session.query(svc.Contact.id).filter_by(id=contact_id).with_for_update().first()
            enrollment = Enrollment.query.filter_by(id=enrollment.id).populate_existing().with_for_update().first()
            step = Step.query.filter_by(id=sid).populate_existing().with_for_update().first()
            if step.lease_token != token or step.status != 'checking': db.session.rollback(); continue
            enrollment = Enrollment.query.filter_by(id=step.enrollment_id).populate_existing().first()
            reason = guard(enrollment, step)
            if not ready or reason:
                stop(enrollment, reason or 'Inbox check incomplete'); db.session.commit(); continue
            user = db.session.get(svc.User, uid)
            if out.limits_for(user)['remaining'] < 1:
                step.status='waiting';step.due_at=next_window(out.day_bounds()[1],cfg['start_hour'],cfg['end_hour']);db.session.commit();continue
            if enrollment.campaign_id != 'standard':
                campaign = db.session.get(svc.OutreachCampaign, enrollment.campaign_id)
                if not campaign or campaign.archived: stop(enrollment, 'Campaign unavailable'); db.session.commit(); continue
                if out.campaign_used(uid, campaign.id) >= campaign.daily_limit:
                    step.status='waiting';step.due_at=next_window(out.day_bounds()[1],cfg['start_hour'],cfg['end_hour']);db.session.commit();continue
            ledger = svc.ContactOutreachLedger.query.filter_by(campaign_id=enrollment.campaign_id, contact_id=contact_id, step='followup-'+str(step.number)).first()
            if ledger:
                previous = db.session.get(out.OutreachRecipient, ledger.recipient_id)
                if previous.status not in ('cancelled','skipped','failed') or out.OutreachAttempt.query.filter_by(recipient_id=previous.id, status='unconfirmed').first():
                    stop(enrollment, 'This campaign step is already reserved or sent'); db.session.commit(); continue
            if out.OutreachRecipient.query.filter_by(email=json.loads(enrollment.snapshot)['email']).filter(out.OutreachRecipient.status.in_(('queued','sending'))).first(): step.status='waiting'; db.session.commit(); continue
            snap, content = json.loads(enrollment.snapshot), json.loads(step.content)
            batch = out.OutreachBatch(user_id=uid, kind='sequence', campaign_id=enrollment.campaign_id,
                status='queued', worker_token=str(uuid.uuid4()))
            db.session.add(batch); db.session.flush()
            recipient = out.OutreachRecipient(batch_id=batch.id, position=0, school_id=school_id, school_name=snap['school_name'], email=snap['email'],
                status='queued', subject=content['subject'], body=content['body'], attachments=json.dumps(content['pdf_files']),
                contact_id=contact_id, contact_link_id=snap['link_id'], contact_version=snap['contact_version'], link_version=snap['link_version'],
                ownership_version=snap['ownership_version'], followup_of_email_id=enrollment.original_id)
            db.session.add(recipient); db.session.flush()
            if ledger: ledger.recipient_id = recipient.id
            else: db.session.add(svc.ContactOutreachLedger(campaign_id=enrollment.campaign_id, contact_id=contact_id, step='followup-'+str(step.number), recipient_id=recipient.id))
            step.recipient_id, step.status, step.lease_until = recipient.id, 'queued', None
            db.session.commit(); queued += 1
        return queued

    svc.sequence_send_guard, svc.sequence_result, svc.schedule_sequences = send_guard, result, schedule_due
    svc.pause_sequence_recipient = pause_recipient
    svc.sequence_dispatch_time = dispatch_time
