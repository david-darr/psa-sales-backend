"""In-app support: bug reports, questions and error reports emailed to the PSA Sales owner.

Every report is saved first, so nothing is lost if email delivery fails. Delivery tries
the reporter's own connected Gmail (replies then go straight back to them), then the
app's system mailbox when MAIL_USERNAME/MAIL_PASSWORD are configured.
"""

import logging
import os
from datetime import timedelta

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

log = logging.getLogger(__name__)

DEFAULT_SUPPORT_EMAIL = 'davidmichael.darr@gmail.com'
KINDS = ('bug', 'question', 'idea', 'error')
HOURLY_LIMIT = 10
LIMITS = {'subject': 160, 'message': 5000, 'page': 300, 'error': 2000, 'browser': 300}


def support_email():
    return (os.getenv('SUPPORT_EMAIL') or DEFAULT_SUPPORT_EMAIL).strip()


def register_support_routes(app, db, svc):
    class SupportReport(db.Model):
        __tablename__ = 'support_reports'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
        kind = db.Column(db.String(12), nullable=False)
        subject = db.Column(db.String(160), nullable=False)
        message = db.Column(db.Text, nullable=False)
        page = db.Column(db.String(300))
        error = db.Column(db.Text)
        browser = db.Column(db.String(300))
        delivered = db.Column(db.Boolean, nullable=False, default=False)
        created_at = db.Column(db.DateTime, nullable=False, default=lambda: svc.utc_now())

    def compose(user, report):
        lines = [
            f'{report.kind.title()} report from {user.name} <{user.email}>',
            f'Page: {report.page or "not given"}',
            f'Time (UTC): {report.created_at:%Y-%m-%d %H:%M}',
            f'Browser: {report.browser or "not given"}',
            '',
            report.message,
        ]
        if report.error:
            lines += ['', 'Error shown in the app:', report.error]
        lines += ['', f'Report #{report.id}. Reply to this email to answer {user.name.split()[0]}.']
        return f'[PSA Sales {report.kind}] {report.subject}', '\n'.join(lines)

    def deliver(user, subject, body):
        """Returns how the report was sent, or None when no mailbox could send it."""
        if user.email_password:
            try:
                if svc.send_email_with_attachments(
                        from_email=user.email, from_password=svc.user_mail_password(user),
                        to_email=support_email(), subject=subject, body=body, pdf_files=[],
                        from_name=user.name):
                    return 'reporter'
            except Exception:
                log.exception('Support report could not be sent from the reporter mailbox')
        if app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD'):
            try:
                svc.mail.send(svc.Message(subject=subject, recipients=[support_email()], body=body,
                                          reply_to=user.email))
                return 'system'
            except Exception:
                log.exception('Support report could not be sent from the system mailbox')
        return None

    @app.post('/api/support')
    @jwt_required()
    def create_support_report():
        user = db.session.get(svc.User, int(get_jwt_identity()))
        if not user:
            return jsonify(error='User not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='Describe the problem or question'), 400
        kind = data.get('kind', 'bug')
        if kind not in KINDS:
            return jsonify(error='Choose bug, question, idea or error'), 400
        values = {}
        for field, limit in LIMITS.items():
            value = data.get(field)
            if value is not None and not isinstance(value, str):
                return jsonify(error=f'{field} must be text'), 400
            values[field] = (value or '').strip()[:limit]
        if not values['message'] and not values['error']:
            return jsonify(error='Describe what happened'), 400
        if not values['subject']:
            values['subject'] = (values['error'] or values['message']).splitlines()[0][:120]
        recent = SupportReport.query.filter(
            SupportReport.user_id == user.id,
            SupportReport.created_at >= svc.utc_now() - timedelta(hours=1)).count()
        if recent >= HOURLY_LIMIT:
            return jsonify(error='You have sent several reports in the last hour. Try again later or email '
                                 + support_email() + ' directly.'), 429
        report = SupportReport(user_id=user.id, kind=kind, subject=values['subject'],
                               message=values['message'] or '(no description)', page=values['page'] or None,
                               error=values['error'] or None, browser=values['browser'] or None)
        db.session.add(report)
        db.session.commit()
        subject, body = compose(user, report)
        via = deliver(user, subject, body)
        report.delivered = bool(via)
        db.session.commit()
        return jsonify(id=report.id, delivered=bool(via), via=via, support_email=support_email()), 201

    @app.get('/api/support')
    @jwt_required()
    def list_support_reports():
        user = db.session.get(svc.User, int(get_jwt_identity()))
        if not user or not user.admin:
            return jsonify(error='Administrator access required'), 403
        rows = db.session.query(SupportReport, svc.User.name).outerjoin(
            svc.User, svc.User.id == SupportReport.user_id).order_by(
            SupportReport.created_at.desc(), SupportReport.id.desc()).limit(50).all()
        return jsonify([{
            'id': report.id, 'kind': report.kind, 'subject': report.subject, 'message': report.message,
            'page': report.page, 'error': report.error, 'delivered': report.delivered,
            'reporter': name, 'created_at': report.created_at.isoformat() + 'Z',
        } for report, name in rows])

    return SupportReport
