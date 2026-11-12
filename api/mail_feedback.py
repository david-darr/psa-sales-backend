"""Conservative feedback handling for SMTP/IMAP, plus an auditable manual stop.

No provider complaint feed is assumed. Only matched delivery reports and human
replies enter here; arbitrary incoming mail never suppresses a contact.
"""
from .sales_workspaces import across_sales_areas
import hashlib
import re

from flask import jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import update


def reply_signal(text):
    # Ignore quoted history. A quoted unsubscribe footer isn't a stop request.
    top = re.split(r'(?im)^\s*(?:>|On .+wrote:|From:|-----Original Message-----)', text or '')[0].strip()
    if re.search(r"(?i)\b(unsubscribe|remove (?:me|us|my email|our email)|do not (?:email|contact)|don't (?:email|contact)|stop (?:emailing|contacting|sending))\b", top):
        return 'optout'
    if re.search(r'(?i)\b(not interested|wrong person|no longer (?:here|works|with)|please stop)\b', top):
        return 'review'
    return None


def hard_bounce(error):
    values = getattr(error, 'recipients', None)
    detail = ' '.join(str(value) for value in values.values()) if values else str(error)
    return bool(re.search(r'\b5\.1\.1\b', detail))


def register_mail_feedback(app, db, svc, out):
    class Signal(db.Model):
        __tablename__ = 'mail_contact_signals'
        id = db.Column(db.Integer, primary_key=True)
        contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'), nullable=False)
        kind = db.Column(db.String(20), nullable=False)
        source = db.Column(db.String(100), nullable=False, unique=True)
        detail = db.Column(db.Text, nullable=False)
        actor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
        created_at = db.Column(db.DateTime, nullable=False, default=out.now)

    svc.MailContactSignal = Signal

    @across_sales_areas
    def record(address, kind, source, detail, actor_id=None, batch_id=None):
        identity = svc.Contact.query.filter_by(email=address.strip().casefold()).first()
        if identity is None: return False
        school_ids = db.session.query(svc.SchoolContact.school_id).filter_by(contact_id=identity.id)
        db.session.query(svc.SalesSchool.id).filter(svc.SalesSchool.id.in_(school_ids)).order_by(
            svc.SalesSchool.id).with_for_update().all()
        contact = svc.Contact.query.filter_by(id=identity.id).populate_existing().with_for_update().first()
        if contact is None or Signal.query.filter_by(source=source).first(): return False
        reason = {'hard_bounce': 'Address rejected: hard bounce', 'optout': 'Recipient asked to stop',
                  'complaint': 'Reported complaint', 'review': 'Contact requires review before more outreach'}[kind]
        contact.do_not_contact, contact.suppression_reason = True, reason
        contact.version += 1
        db.session.add(Signal(contact_id=contact.id, kind=kind, source=source, detail=detail[:1000], actor_id=actor_id))
        db.session.add(svc.ContactEvent(contact_id=contact.id, actor_id=actor_id, detail=reason))
        recipients = out.OutreachRecipient.query.join(out.OutreachBatch).filter(out.OutreachRecipient.email == contact.email,
            out.OutreachBatch.status.in_(('queued', 'sending'))).all()
        batches = {r.batch_id for r in recipients}
        if batch_id: batches.add(batch_id)
        db.session.query(out.OutreachBatch.id).filter(out.OutreachBatch.id.in_(batches)).order_by(
            out.OutreachBatch.id).with_for_update().all()
        for recipient in recipients:
            if recipient.status == 'queued': recipient.status, recipient.error = 'cancelled', reason
        if batches:
            db.session.execute(update(out.OutreachBatch).where(out.OutreachBatch.id.in_(batches),
                out.OutreachBatch.status.in_(('queued', 'sending'))).values(status='paused', paused_reason=reason, heartbeat_at=out.now()))
        if kind == 'optout':
            school_ids = db.session.query(svc.SchoolContact.school_id).filter_by(contact_id=contact.id)
            for school in svc.SalesSchool.query.filter(svc.SalesSchool.id.in_(school_ids),
                svc.SalesSchool.status.in_(('pending', 'contacted', 'replied'))).all():
                school.status = 'not_interested'
                db.session.add(svc.SchoolActivity(sales_school_id=school.id, actor_id=actor_id,
                    kind='unsubscribed', detail='Recipient asked to stop. Contact suppression applies across schools.'))
        return True

    def delivery_report(message, outbound_by_id, user_id):
        if message.get_content_type() != 'multipart/report' or message.get_param('report-type') != 'delivery-status':
            return False
        original_ids, rejected = set(), set()
        for part in message.walk():
            if part.get_content_type() == 'message/delivery-status':
                for block in part.get_payload() or []:
                    if str(block.get('Action', '')).lower() == 'failed' and str(block.get('Status', '')).strip() == '5.1.1':
                        address = str(block.get('Final-Recipient', '')).split(';')[-1].strip().casefold()
                        rejected.add(address)
                    if block.get('Original-Message-ID'): original_ids.add(str(block['Original-Message-ID']).strip())
            if part.get_content_type() in ('message/rfc822', 'text/rfc822-headers'):
                payload = part.get_payload()
                if isinstance(payload, list):
                    original_ids.update(str(item.get('Message-ID', '')).strip() for item in payload)
                elif isinstance(payload, str):
                    original_ids.update(re.findall(r'(?im)^Message-ID:\s*(<[^>]+>)', payload))
        changed = False
        for original_id in original_ids:
            sent = outbound_by_id.get(original_id)
            if sent is not None and sent.user_id == user_id and sent.school_email.strip().casefold() in rejected:
                source = 'dsn:' + hashlib.sha256((str(user_id) + original_id + sent.school_email).encode()).hexdigest()
                changed |= record(sent.school_email, 'hard_bounce', source, 'Matched delivery report: 5.1.1', actor_id=user_id)
        return changed

    svc.record_mail_signal, svc.process_delivery_report = record, delivery_report

    @app.post('/api/contacts/<int:contact_id>/report')
    @jwt_required()
    def report(contact_id):
        user = out.current_user()
        if user is None: return jsonify(error='User not found'), 404
        visible = db.session.query(svc.SchoolContact.id).join(svc.SalesSchool).filter(
            svc.SchoolContact.contact_id == contact_id)
        if not user.admin: visible = visible.filter(svc.SalesSchool.user_id == user.id)
        contact = db.session.get(svc.Contact, contact_id)
        if contact is None or visible.first() is None: return jsonify(error='Contact not found'), 404
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict): return jsonify(error='Supply a report object'), 400
        kind, detail = data.get('kind'), data.get('detail')
        if kind not in ('optout', 'complaint', 'review') or not isinstance(detail, str) or not 10 <= len(detail.strip()) <= 1000:
            return jsonify(error='Choose a stop/complaint/review reason and explain the source'), 400
        import uuid
        record(contact.email, kind, 'manual:' + str(uuid.uuid4()), detail.strip(), actor_id=user.id)
        db.session.commit()
        return jsonify(suppressed=True)
