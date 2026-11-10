"""Employee-bound Gmail authorization. Disabled until configured explicitly.

An authorization alone never switches the production sender. Reply syncing and
the scheduled HTTPS worker must be ready before a connection can be activated.
"""
import base64
import hashlib
import os
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import requests
from flask import jsonify, make_response, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import update

from .gmail_https import API_URL, TOKEN_URL

SCOPES = frozenset(('https://www.googleapis.com/auth/gmail.send',
                    'https://www.googleapis.com/auth/gmail.readonly'))
AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'


def configured():
    return os.getenv('GMAIL_OAUTH_ENABLED', 'false').lower() == 'true'


def settings():
    values = [os.getenv(key, '').strip() for key in (
        'GMAIL_OAUTH_CLIENT_ID', 'GMAIL_OAUTH_CLIENT_SECRET', 'GMAIL_OAUTH_REDIRECT_URI')]
    if not all(values):
        raise ValueError('Google mail connection has not been configured by an administrator')
    uri = urlsplit(values[2])
    local = uri.hostname in ('127.0.0.1', 'localhost')
    if (uri.scheme != 'https' and not (local and uri.scheme == 'http')) or not uri.hostname or uri.username or uri.password or uri.query or uri.fragment:
        raise ValueError('Google mail redirect URI must be a fixed HTTPS callback URL')
    return values


def register_gmail_oauth(app, db, svc):
    class Connection(db.Model):
        __tablename__ = 'gmail_connections'
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
        mailbox = db.Column(db.String(320))
        refresh_token_cipher = db.Column(db.Text)
        authorized_at = db.Column(db.DateTime)
        revoked_at = db.Column(db.DateTime)
        generation = db.Column(db.Integer, nullable=False, default=0)
        pending_id = db.Column(db.String(64))
        active = db.Column(db.Boolean, nullable=False, default=False)

    class Ticket(db.Model):
        __tablename__ = 'gmail_authorizations'
        id = db.Column(db.String(64), primary_key=True)  # SHA-256 of random state
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
        generation = db.Column(db.Integer, nullable=False)
        verifier_cipher = db.Column(db.Text, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False)
        consumed_at = db.Column(db.DateTime)

    svc.GmailConnection, svc.GmailAuthorization = Connection, Ticket

    def employee():
        try:
            return db.session.get(svc.User, int(get_jwt_identity()))
        except (TypeError, ValueError):
            return None

    @app.after_request
    def protect_google_connection_response(response):
        if request.path.startswith('/api/mail/google/'):
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.get('/api/mail/google/status')
    @jwt_required()
    def status():
        user = employee()
        if user is None:
            return jsonify(error='User not found'), 404
        # No table queries until the feature/migration is deliberately enabled.
        if not configured():
            return jsonify(enabled=False, authorized=False, active=False)
        connection = db.session.get(Connection, user.id)
        authorized = bool(connection and connection.refresh_token_cipher and not connection.revoked_at)
        return jsonify(enabled=True, authorized=authorized, active=False,
            mailbox=connection.mailbox if authorized else None,
            status='authorized_pending_activation' if authorized else 'not_connected',
            note='Google authorization does not enable sending until HTTPS reply sync and scheduling are ready.')

    @app.post('/api/mail/google/connect')
    @jwt_required()
    def begin():
        if not configured():
            return jsonify(error='Google mail connection is not enabled'), 503
        user = employee()
        if user is None:
            return jsonify(error='User not found'), 404
        try:
            client_id, _secret, redirect_uri = settings()
        except ValueError as exc:
            return jsonify(error=str(exc)), 503
        # Lock an existing parent row even when no connection exists yet.
        db.session.query(svc.User).filter_by(id=user.id).with_for_update().one()
        connection = db.session.get(Connection, user.id)
        if connection is None:
            connection = Connection(user_id=user.id, generation=0)
            db.session.add(connection)
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        digest = hashlib.sha256(state.encode()).hexdigest()
        connection.generation += 1
        connection.pending_id = digest
        db.session.add(Ticket(id=digest, user_id=user.id, generation=connection.generation,
            verifier_cipher=svc.encrypt_password(verifier), expires_at=svc.utc_now() + timedelta(minutes=10)))
        # Clean up already-consumed/expired tickets; tokens never leave encrypted storage.
        Ticket.query.filter(Ticket.expires_at < svc.utc_now()).delete(synchronize_session=False)
        db.session.commit()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        url = AUTH_URL + '?' + urlencode(dict(client_id=client_id, redirect_uri=redirect_uri,
            response_type='code', scope=' '.join(sorted(SCOPES)), access_type='offline',
            prompt='consent select_account', state=state, code_challenge=challenge,
            code_challenge_method='S256', login_hint=user.email))
        return jsonify(authorization_url=url, expires_in_seconds=600)

    def callback_failure():
        return make_response('Google mail was not connected. Start a new connection from your private account controls.', 400)

    @app.get('/api/mail/google/callback')
    def callback():
        if not configured():
            return make_response('Google mail connection is not enabled.', 503)
        state, code = request.args.get('state', ''), request.args.get('code', '')
        if not 32 <= len(state) <= 128:
            return callback_failure()
        digest = hashlib.sha256(state.encode()).hexdigest()
        now = svc.utc_now()
        # Claim before contacting Google. Replays and simultaneous callbacks lose.
        claimed = db.session.execute(update(Ticket).where(Ticket.id == digest,
            Ticket.consumed_at.is_(None), Ticket.expires_at > now).values(consumed_at=now)).rowcount
        db.session.commit()
        if claimed != 1:
            return callback_failure()
        ticket = db.session.get(Ticket, digest)
        user = db.session.get(svc.User, ticket.user_id)
        connection = db.session.get(Connection, ticket.user_id)
        if (not user or not connection or connection.pending_id != digest or
                connection.generation != ticket.generation or not code or len(code) > 4096 or request.args.get('error')):
            return callback_failure()
        uid, expected_email, generation = user.id, user.email.casefold(), ticket.generation
        try:
            client_id, secret, redirect_uri = settings()
            verifier = svc.decrypt_password(ticket.verifier_cipher)
            db.session.rollback()  # No pooled DB connection during Google calls.
            response = requests.post(TOKEN_URL, data=dict(client_id=client_id,
                client_secret=secret, redirect_uri=redirect_uri, grant_type='authorization_code',
                code=code, code_verifier=verifier), timeout=(5, 15), allow_redirects=False)
            if response.status_code != 200:
                return callback_failure()
            data = response.json()
            if not isinstance(data, dict) or not SCOPES.issubset(set(str(data.get('scope', '')).split())):
                return callback_failure()
            refresh, access = data.get('refresh_token'), data.get('access_token')
            if not all(isinstance(value, str) and value for value in (refresh, access)):
                return callback_failure()
            profile = requests.get(API_URL + '/profile', headers={'Authorization': 'Bearer ' + access},
                timeout=(5, 15), allow_redirects=False)
            if profile.status_code != 200:
                return callback_failure()
            profile_data = profile.json()
            if not isinstance(profile_data, dict) or str(profile_data.get('emailAddress', '')).casefold() != expected_email:
                return callback_failure()
            # A newer connection or disconnect wins over an in-flight callback.
            saved = db.session.execute(update(Connection).where(Connection.user_id == uid,
                Connection.pending_id == digest, Connection.generation == generation).values(
                    mailbox=expected_email, refresh_token_cipher=svc.encrypt_password(refresh),
                    authorized_at=svc.utc_now(), revoked_at=None, pending_id=None, active=False)).rowcount
            db.session.commit()
            if saved != 1:
                return callback_failure()
        except (requests.RequestException, ValueError, TypeError, svc.MailCredentialUnavailable):
            db.session.rollback()
            return callback_failure()
        return make_response('Google mail authorization saved. Sending remains inactive until the HTTPS mail rollout is complete. You can close this window.', 200)

    @app.post('/api/mail/google/disconnect')
    @jwt_required()
    def disconnect():
        if not configured():
            return jsonify(error='Google mail connection is not enabled'), 503
        user = employee()
        if user is None:
            return jsonify(error='User not found'), 404
        db.session.query(svc.User).filter_by(id=user.id).with_for_update().one()
        connection = db.session.get(Connection, user.id)
        if connection:
            connection.generation += 1
            connection.pending_id = connection.refresh_token_cipher = None
            connection.revoked_at, connection.active = svc.utc_now(), False
        Ticket.query.filter_by(user_id=user.id).delete(synchronize_session=False)
        db.session.commit()
        return jsonify(disconnected=True, provider_revoked=False,
            note='Local authorization removed. Google account access can also be removed in Google Account security settings.')

    return Connection, Ticket
