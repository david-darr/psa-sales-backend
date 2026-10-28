"""Personal API keys and the versioned agent API under /api/agent/v1.

A key belongs to the employee who created it and carries their *current* role
on every request: an administrator's key sees the whole team, a rep's key sees
only that rep's records. Each v1 endpoint authenticates the key, checks its
scope, then runs the same handler the web app uses (crm.py, the school
workspace, outreach) under a short-lived in-process token for that employee.
Permissions, validation and version checks therefore cannot drift from the UI.
That token never leaves the server.

Keys are shown once, stored as SHA-256 hashes, expire after 7/30/90 days and
can be revoked. Every request is audited (key, employee, route, status) without
request or response content. The audit table also backs the per-key rate limit,
so the limit holds across worker processes.

Email sending is not exposed in v1: outreach is read-only.
"""

import hashlib
import os
import re
import secrets
from datetime import timedelta

from flask import g, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from sqlalchemy.exc import OperationalError, ProgrammingError

KEY_PREFIX = 'psak_'
KEY_PATTERN = re.compile(r'^psak_[0-9a-f]{64}$')
EXPIRY_DAYS = (7, 30, 90)
SCOPES = {'read': 'read', 'write': 'read,write'}
MAX_ACTIVE_KEYS = 10
RATE_LIMIT_PER_MINUTE = 60
MAX_BODY_BYTES = 32 * 1024
BASE = '/api/agent/v1'

# Query parameters each read endpoint forwards to the underlying handler.
SCHOOL_FILTERS = ('q', 'stage', 'owner', 'type', 'due', 'sort', 'page', 'limit', 'scope', 'today')
TASK_FILTERS = ('view', 'school_id', 'page', 'limit', 'scope', 'today')
SCHOOL_UPDATE_FIELDS = ('status', 'next_action', 'next_action_at', 'user_id')


def enabled():
    return os.getenv('AGENT_API_ENABLED', 'true').strip().lower() not in ('0', 'false', 'no', 'off')


def hash_key(token):
    return hashlib.sha256(token.encode()).hexdigest()


def register_agent_api(app, db, User, utc_now):
    class AgentApiKey(db.Model):
        __tablename__ = 'agent_api_keys'
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
        name = db.Column(db.String(80), nullable=False)
        key_hash = db.Column(db.String(64), unique=True, nullable=False)
        key_hint = db.Column(db.String(20), nullable=False)
        scopes = db.Column(db.String(40), nullable=False, default='read')
        created_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())
        expires_at = db.Column(db.DateTime, nullable=False)
        revoked_at = db.Column(db.DateTime)
        last_used_at = db.Column(db.DateTime)

    class AgentApiAudit(db.Model):
        __tablename__ = 'agent_api_audit'
        __table_args__ = (db.Index('ix_agent_api_audit_key_time', 'key_id', 'created_at'),)
        id = db.Column(db.Integer, primary_key=True)
        key_id = db.Column(db.Integer, db.ForeignKey('agent_api_keys.id', ondelete='CASCADE'), nullable=False)
        user_id = db.Column(db.Integer, nullable=False)
        method = db.Column(db.String(8), nullable=False)
        route = db.Column(db.String(120), nullable=False)
        status = db.Column(db.Integer, nullable=False)
        created_at = db.Column(db.DateTime, nullable=False, default=lambda: utc_now())

    def key_dict(key):
        return {
            'id': key.id, 'name': key.name, 'hint': key.key_hint,
            'scope': 'write' if 'write' in key.scopes.split(',') else 'read',
            'created_at': key.created_at.isoformat() + 'Z',
            'expires_at': key.expires_at.isoformat() + 'Z',
            'last_used_at': key.last_used_at.isoformat() + 'Z' if key.last_used_at else None,
            'revoked': key.revoked_at is not None,
            'expired': key.expires_at <= utc_now(),
        }

    def unavailable():
        db.session.rollback()
        return jsonify(error='AI integrations are not set up yet. Ask your PSA administrator.'), 503

    # -- Key management (signed-in web session) ---------------------------------

    @app.route('/api/agent-keys', methods=['GET', 'POST'])
    @jwt_required()
    def agent_keys():
        if not enabled():
            return jsonify(error='AI integrations are turned off.'), 503
        user = db.session.get(User, int(get_jwt_identity()))
        if not user:
            return jsonify(error='User not found'), 404
        try:
            if request.method == 'GET':
                keys = AgentApiKey.query.filter_by(user_id=user.id).filter(
                    AgentApiKey.revoked_at.is_(None)).order_by(AgentApiKey.created_at.desc(), AgentApiKey.id.desc()).all()
                return jsonify(items=[key_dict(key) for key in keys], base_url=request.host_url.rstrip('/') + BASE)
            data = request.get_json(silent=True)
            if not isinstance(data, dict) or set(data) - {'name', 'scope', 'expires_in_days'}:
                return jsonify(error='Supply a name, scope and expiry'), 400
            name = data.get('name')
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
                return jsonify(error='Enter a key name under 80 characters'), 400
            if data.get('scope') not in SCOPES:
                return jsonify(error='Choose read or write access'), 400
            if data.get('expires_in_days') not in EXPIRY_DAYS or type(data.get('expires_in_days')) is not int:
                return jsonify(error='Choose an expiry of 7, 30 or 90 days'), 400
            active = AgentApiKey.query.filter(AgentApiKey.user_id == user.id, AgentApiKey.revoked_at.is_(None),
                                              AgentApiKey.expires_at > utc_now()).count()
            if active >= MAX_ACTIVE_KEYS:
                return jsonify(error=f'You can have up to {MAX_ACTIVE_KEYS} active keys. Revoke one first.'), 400
            token = KEY_PREFIX + secrets.token_hex(32)
            key = AgentApiKey(user_id=user.id, name=name.strip(), key_hash=hash_key(token),
                              key_hint=token[:9] + '...' + token[-4:], scopes=SCOPES[data['scope']],
                              expires_at=utc_now() + timedelta(days=data['expires_in_days']))
            db.session.add(key)
            db.session.commit()
            # The only time the full key is returned. It is never stored or logged.
            return jsonify(key=token, **key_dict(key)), 201
        except (ProgrammingError, OperationalError):
            return unavailable()

    @app.delete('/api/agent-keys/<int:key_id>')
    @jwt_required()
    def revoke_agent_key(key_id):
        user = db.session.get(User, int(get_jwt_identity()))
        if not user:
            return jsonify(error='User not found'), 404
        try:
            key = AgentApiKey.query.filter_by(id=key_id, user_id=user.id).first()
            if not key:
                return jsonify(error='Key not found'), 404
            if key.revoked_at is None:
                key.revoked_at = utc_now()
                db.session.commit()
            return jsonify(key_dict(key))
        except (ProgrammingError, OperationalError):
            return unavailable()

    # -- Agent requests ----------------------------------------------------------

    def authenticate(write):
        """Return (key, user, None) or (None, None, error response)."""
        if not enabled():
            return None, None, (jsonify(error='The PSA agent API is turned off'), 503)
        header = request.headers.get('Authorization', '')
        token = header[7:].strip() if header.startswith('Bearer ') else ''
        if not KEY_PATTERN.match(token):
            return None, None, (jsonify(error='Invalid, expired, or revoked API key'), 401)
        try:
            key = AgentApiKey.query.filter_by(key_hash=hash_key(token)).first()
        except (ProgrammingError, OperationalError):
            db.session.rollback()
            return None, None, (jsonify(error='The PSA agent API is not set up yet'), 503)
        now = utc_now()
        if not key or key.revoked_at is not None or key.expires_at <= now:
            return None, None, (jsonify(error='Invalid, expired, or revoked API key'), 401)
        user = db.session.get(User, key.user_id)
        if not user:
            return None, None, (jsonify(error='Invalid, expired, or revoked API key'), 401)
        recent = AgentApiAudit.query.filter(AgentApiAudit.key_id == key.id,
                                            AgentApiAudit.created_at > now - timedelta(minutes=1)).count()
        if recent >= RATE_LIMIT_PER_MINUTE:
            response = jsonify(error='Rate limit reached. Try again in a minute.')
            response.headers['Retry-After'] = '60'
            return key, user, (response, 429)
        if write and 'write' not in key.scopes.split(','):
            return key, user, (jsonify(error='This key is read-only'), 403)
        if request.content_length and request.content_length > MAX_BODY_BYTES:
            return key, user, (jsonify(error='Request too large'), 413)
        return key, user, None

    def audit(key, user, route, status):
        # Route templates only: never URLs with IDs or queries, bodies, or results.
        try:
            db.session.rollback()
            key = db.session.get(AgentApiKey, key.id)
            key.last_used_at = utc_now()
            db.session.add(AgentApiAudit(key_id=key.id, user_id=user.id, method=request.method,
                                         route=route[:120], status=status))
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.warning('Agent API audit write failed for key %s', key.id)

    def delegate(endpoint, user, *, method='GET', args=None, body=None, view_args=None):
        """Run a web-app handler as this employee and return (payload, status)."""
        view = app.view_functions.get(endpoint)
        if view is None:
            return {'error': 'This feature is not available yet'}, 404
        token = create_access_token(identity=str(user.id), expires_delta=timedelta(seconds=60),
                                    additional_claims={'via': 'agent_api'})
        query = {name: value for name, value in (args or {}).items() if value is not None}
        with app.test_request_context(request.path, method=method, query_string=query,
                                      json=body if method != 'GET' else None,
                                      headers={'Authorization': 'Bearer ' + token}):
            response = app.make_response(view(**(view_args or {})))
        return response.get_json(silent=True), response.status_code

    def agent_route(rule, methods, name, write=False):
        def wrap(handler):
            def endpoint(**kwargs):
                key, user, error = authenticate(write or request.method != 'GET')
                if error:
                    response, status = error
                    if key is not None:
                        audit(key, user, f'{request.method} {rule}', status)
                    return response, status
                g.agent_key = key
                try:
                    payload, status = handler(user, **kwargs)
                except Exception:
                    db.session.rollback()
                    app.logger.exception('Agent API handler failed: %s %s', request.method, rule)
                    payload, status = {'error': 'Request failed'}, 500
                audit(key, user, f'{request.method} {rule}', status)
                return jsonify(payload), status
            endpoint.__name__ = 'agent_v1_' + name
            app.add_url_rule(BASE + rule, endpoint.__name__, endpoint, methods=methods)
            return handler
        return wrap

    def forwarded(names):
        return {name: request.args.get(name) for name in names}

    def body():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else None

    @agent_route('/me', ['GET'], 'me')
    def agent_me(user):
        return {'id': user.id, 'name': user.name, 'email': user.email,
                'role': 'admin' if user.admin else 'rep', 'admin': bool(user.admin),
                'api_version': 'v1', 'key': {k: v for k, v in key_dict(g.agent_key).items()
                                             if k in ('name', 'scope', 'expires_at')}}, 200

    @agent_route('/team', ['GET'], 'team')
    def agent_team(user):
        if not user.admin:
            return {'error': 'Administrator access required'}, 403
        return delegate('crm_team', user, args=forwarded(('today',)))

    @agent_route('/schools', ['GET'], 'schools')
    def agent_schools(user):
        return delegate('crm_schools', user, args=forwarded(SCHOOL_FILTERS))

    @agent_route('/schools/<int:school_id>', ['GET', 'PATCH'], 'school')
    def agent_school(user, school_id):
        if request.method == 'GET':
            return delegate('sales_school_workspace', user, view_args={'school_id': school_id})
        data = body()
        if not data or set(data) - set(SCHOOL_UPDATE_FIELDS):
            return {'error': 'Update status, next_action, next_action_at or user_id'}, 400
        return delegate('sales_school_workspace', user, method='PATCH', body=data,
                        view_args={'school_id': school_id})

    @agent_route('/schools/assign', ['POST'], 'assign', write=True)
    def agent_assign(user):
        if not user.admin:
            return {'error': 'Only administrators can reassign schools'}, 403
        data = body()
        if not data or set(data) != {'ids', 'user_id'}:
            return {'error': 'Supply ids and user_id'}, 400
        return delegate('crm_bulk_schools', user, method='POST', body=data)

    @agent_route('/schools/<int:school_id>/activities', ['POST'], 'activity', write=True)
    def agent_activity(user, school_id):
        data = body()
        if not data or set(data) != {'kind', 'detail'}:
            return {'error': 'Supply kind (note, call or meeting) and detail'}, 400
        return delegate('add_school_activity', user, method='POST', body=data, view_args={'school_id': school_id})

    @agent_route('/pipeline', ['GET'], 'pipeline')
    def agent_pipeline(user):
        return delegate('crm_overview', user, args=forwarded(('scope', 'today')))

    @agent_route('/tasks', ['GET', 'POST'], 'tasks')
    def agent_tasks(user):
        if request.method == 'GET':
            return delegate('crm_tasks', user, args=forwarded(TASK_FILTERS))
        data = body()
        if data is None:
            return {'error': 'Supply a task'}, 400
        return delegate('crm_tasks', user, method='POST', body=data)

    @agent_route('/tasks/<int:task_id>', ['PATCH'], 'task')
    def agent_task(user, task_id):
        data = body()
        if data is None:
            return {'error': 'Supply version and a status or due date'}, 400
        return delegate('crm_update_task', user, method='PATCH', body=data, view_args={'task_id': task_id})

    @agent_route('/outreach', ['GET'], 'outreach')
    def agent_outreach(user):
        return delegate('outreach_list_batches', user, args=forwarded(('limit', 'scope')))

    @agent_route('/outreach/<int:batch_id>', ['GET'], 'outreach_batch')
    def agent_outreach_batch(user, batch_id):
        return delegate('outreach_get_batch', user, view_args={'batch_id': batch_id})

    @agent_route('/accounts', ['GET'], 'accounts')
    def agent_accounts(user):
        if not user.admin:
            return {'error': 'Administrator access required'}, 403
        return delegate('crm_portfolio', user, args=forwarded(('scope',)))

    @agent_route('/commissions', ['GET'], 'commissions')
    def agent_commissions(user):
        if not user.admin:
            return {'error': 'Administrator access required'}, 403
        if 'admin_commissions' not in app.view_functions:
            return {'error': 'Commissions are not available yet', 'available': False}, 404
        payload, status = delegate('admin_commissions', user, args=forwarded(('from', 'to')))
        if status == 200 and isinstance(payload, dict):
            # Summary only: per-close detail stays in the web app.
            payload = {'available': True, 'summary': payload.get('summary'), 'reps': payload.get('reps')}
        return payload, status

    return AgentApiKey, AgentApiAudit
