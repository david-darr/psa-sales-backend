"""Administrator-only rep join links. Seasonal commissions live in program_commissions."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required


JOIN_LINK_DAYS = (1, 7, 14, 30)


def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def naive_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def usable_join_link(model, token, lock=False):
    """The link for this token if it can still create an account, else None."""
    if not isinstance(token, str) or not token or len(token) > 256:
        return None
    query = model.query.filter_by(token_hash=hash_token(token))
    if lock:
        query = query.with_for_update()
    link = query.first()
    if (not link or link.revoked_at or link.expires_at <= naive_utc()
            or (link.max_uses is not None and link.use_count >= link.max_uses)):
        return None
    return link


def register_admin_sales_routes(app, db, User, JoinLink):
    def current_admin():
        user = db.session.get(User, int(get_jwt_identity()))
        return user if user and user.admin else None

    def forbidden():
        return jsonify(error='Administrator access required'), 403

    def link_dict(link):
        now = naive_utc()
        state = 'active'
        if link.revoked_at:
            state = 'revoked'
        elif link.expires_at <= now:
            state = 'expired'
        elif link.max_uses is not None and link.use_count >= link.max_uses:
            state = 'used up'
        return {'id': link.id, 'label': link.label, 'expires_at': link.expires_at.isoformat() + 'Z',
                'max_uses': link.max_uses, 'use_count': link.use_count, 'state': state,
                'created_at': link.created_at.isoformat() + 'Z'}

    @app.get('/api/join-links')
    @jwt_required()
    def list_join_links():
        if not current_admin():
            return forbidden()
        links = JoinLink.query.order_by(JoinLink.created_at.desc(), JoinLink.id.desc()).limit(20).all()
        return jsonify([link_dict(link) for link in links])

    @app.post('/api/join-links')
    @jwt_required()
    def create_join_link():
        admin = current_admin()
        if not admin:
            return forbidden()
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(error='Invalid request'), 400
        days = data.get('days', 7)
        max_uses = data.get('max_uses', 25)
        label = data.get('label')
        if days not in JOIN_LINK_DAYS:
            return jsonify(error='Choose 1, 7, 14 or 30 days'), 400
        if max_uses is not None and (type(max_uses) is not int or not 1 <= max_uses <= 200):
            return jsonify(error='Uses must be between 1 and 200'), 400
        if label is not None and (not isinstance(label, str) or len(label.strip()) > 80):
            return jsonify(error='Keep the label under 80 characters'), 400
        token = secrets.token_urlsafe(32)
        link = JoinLink(token_hash=hash_token(token), label=(label or '').strip() or None,
                        created_by=admin.id, expires_at=naive_utc() + timedelta(days=days), max_uses=max_uses)
        db.session.add(link)
        db.session.commit()
        return jsonify(token=token, **link_dict(link)), 201

    @app.delete('/api/join-links/<int:link_id>')
    @jwt_required()
    def revoke_join_link(link_id):
        if not current_admin():
            return forbidden()
        link = JoinLink.query.filter_by(id=link_id).with_for_update().first()
        if not link:
            return jsonify(error='Link not found'), 404
        if not link.revoked_at:
            link.revoked_at = naive_utc()
            db.session.commit()
        return jsonify(link_dict(link))

    @app.post('/api/join-links/check')
    def check_join_link():
        """Public: lets the sign-up page say whether a shared link still works."""
        data = request.get_json(silent=True)
        token = data.get('token') if isinstance(data, dict) else None
        return jsonify(valid=usable_join_link(JoinLink, token) is not None)
