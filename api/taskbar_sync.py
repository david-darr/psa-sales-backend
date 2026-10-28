"""Two-way sync of sales tasks with Taskbar (migration 20261030_taskbar_sync.sql).

PSA to Taskbar: a per-process background worker pushes tasks whose ``version`` is ahead
of their link row through Taskbar's agent API. Saves only wake the worker; they never
wait on Taskbar. The worker also runs on a timer, so bulk updates that bypass ORM events
(school reassignment) still sync.

Taskbar to PSA: Taskbar's ``psa-sync`` function POSTs HMAC-signed task snapshots to
``/api/integrations/taskbar/webhook``. Echoes of our own writes carry a revision we have
already recorded and are ignored. Conflicts are last-writer-wins on Taskbar's
``updated_at`` versus the time the worker first saw the unpushed PSA change.

Disabled unless TASKBAR_SYNC_ENABLED=true and every required variable is set.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import event, or_, text

log = logging.getLogger('psa.taskbar_sync')

SIGNATURE_TOLERANCE = 300  # seconds of clock skew accepted on signed requests
MAX_WEBHOOK_BYTES = 65536
TASKBAR_TITLE_MAX = 140
PSA_TITLE_MAX = 240
MARKER = re.compile(r'\[psa-task:(\d+)\]')
OPEN_STATUSES = ('Not Started', 'In Progress')
LOCK_KEY = 72616201  # pg advisory lock shared by every web process


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_remote_time(value):
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def iso_z(value):
    return value.replace(microsecond=0).isoformat() + 'Z'


# ----------------------------------------------------------------------------
# Field mapping
# ----------------------------------------------------------------------------

def to_taskbar_status(psa_status, last_remote=None):
    if psa_status == 'completed':
        return 'Completed'
    # PSA has no "in progress"; keep Taskbar's when the task is still open there.
    return last_remote if last_remote in OPEN_STATUSES else 'Not Started'


def to_psa_status(taskbar_status):
    return 'completed' if taskbar_status == 'Completed' else 'open'


def to_taskbar_priority(psa_priority, last_remote=None):
    if psa_priority == 'high':
        return 'High'
    return 'Low' if last_remote == 'Low' else 'Medium'


def to_psa_priority(taskbar_priority):
    return 'high' if taskbar_priority == 'High' else 'normal'


def taskbar_title(psa_title):
    title = (psa_title or '').strip()
    return title if len(title) <= TASKBAR_TITLE_MAX else title[:TASKBAR_TITLE_MAX - 3].rstrip() + '...'


def default_due(task):
    """Taskbar requires a deadline; undated PSA tasks show a week after creation."""
    created = task.created_at or now()
    return created.replace(hour=17, minute=0, second=0, microsecond=0) + timedelta(days=7)


def marker(task_id):
    return f'[psa-task:{task_id}]'


# ----------------------------------------------------------------------------
# Signatures (shared by both directions)
# ----------------------------------------------------------------------------

def sign(secret, timestamp, body):
    digest = hmac.new(secret.encode(), f'{timestamp}.'.encode() + body, hashlib.sha256).hexdigest()
    return 'v1=' + digest


def verify_signature(secret, timestamp, signature, body, current=None):
    if not secret or not timestamp or not signature:
        return False
    try:
        stamp = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((current or time.time()) - stamp) > SIGNATURE_TOLERANCE:
        return False
    return hmac.compare_digest(sign(secret, stamp, body), signature)


class SyncConfig:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        self.api_url = (env.get('TASKBAR_API_URL') or '').rstrip('/')
        self.api_key = env.get('TASKBAR_API_KEY') or ''
        self.sync_url = (env.get('TASKBAR_SYNC_URL') or '').rstrip('/')
        self.secret = env.get('TASKBAR_WEBHOOK_SECRET') or ''
        self.program_id = (env.get('TASKBAR_SALES_PROGRAM_ID') or '').lower()
        self.time_zone = env.get('TASKBAR_TIME_ZONE') or 'America/New_York'
        self.poll_seconds = max(5, int(env.get('TASKBAR_SYNC_POLL_SECONDS') or 20))
        self.enabled = (env.get('TASKBAR_SYNC_ENABLED', '').lower() == 'true'
                        and all((self.api_url.startswith('https://'), self.api_key, self.sync_url.startswith('https://'),
                                 self.secret, self.program_id)))


class TaskbarError(Exception):
    def __init__(self, status, message=''):
        super().__init__(f'{status}: {message}'[:300])
        self.status = status


class TaskbarClient:
    """Agent API calls plus the signed member directory. No redirects, short timeouts."""

    def __init__(self, config, http=None):
        self.config = config
        self.http = http or requests.Session()

    def call(self, method, path, body=None, params=None):
        try:
            response = self.http.request(
                method, self.config.api_url + path, json=body, params=params, timeout=15, allow_redirects=False,
                headers={'Authorization': 'Bearer ' + self.config.api_key})
        except requests.RequestException as exc:
            raise TaskbarError(0, type(exc).__name__)
        try:
            data = response.json()
        except ValueError:
            data = {}
        if response.status_code >= 300:
            raise TaskbarError(response.status_code, data.get('error', '') if isinstance(data, dict) else '')
        return data

    def directory(self):
        body = json.dumps({'program_id': self.config.program_id}).encode()
        stamp = int(time.time())
        try:
            response = self.http.request(
                'POST', self.config.sync_url + '/directory', data=body, timeout=15, allow_redirects=False,
                headers={'Content-Type': 'application/json', 'X-PSA-Sync-Timestamp': str(stamp),
                         'X-PSA-Sync-Signature': sign(self.config.secret, stamp, body)})
        except requests.RequestException as exc:
            raise TaskbarError(0, type(exc).__name__)
        if response.status_code != 200:
            raise TaskbarError(response.status_code, 'directory unavailable')
        return response.json().get('members', [])


def register_taskbar_sync(app, db, User, SalesTask, env=None, client=None):
    config = SyncConfig(env)

    class SalesTaskLink(db.Model):
        __tablename__ = 'sales_task_links'
        sales_task_id = db.Column(db.Integer, db.ForeignKey('sales_tasks.id', ondelete='CASCADE'), primary_key=True)
        taskbar_task_id = db.Column(db.String(36), unique=True)
        taskbar_revision = db.Column(db.BigInteger)
        taskbar_status = db.Column(db.String(20))
        taskbar_priority = db.Column(db.String(10))
        taskbar_updated_at = db.Column(db.DateTime)
        psa_version = db.Column(db.Integer, nullable=False, default=0)  # PSA version Taskbar matches
        dirty_at = db.Column(db.DateTime)  # first time the worker saw an unpushed PSA change
        due_defaulted = db.Column(db.Boolean, nullable=False, default=False)
        origin = db.Column(db.String(10), nullable=False, default='psa')
        state = db.Column(db.String(12), nullable=False, default='pending')  # pending|synced|error|detached
        attempts = db.Column(db.Integer, nullable=False, default=0)
        next_attempt_at = db.Column(db.DateTime)
        last_error = db.Column(db.String(300))
        last_synced_at = db.Column(db.DateTime)
        task = db.relationship(SalesTask)

    class TaskbarUserLink(db.Model):
        __tablename__ = 'taskbar_user_links'
        user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
        taskbar_user_id = db.Column(db.String(36), unique=True, nullable=False)
        matched_at = db.Column(db.DateTime, nullable=False, default=now)

    class Sync:
        """One per process. ``run_once`` is safe to call from several processes at once."""

        def __init__(self):
            self.config = config
            self.client = client or TaskbarClient(config)
            self.wakeup = threading.Event()
            self.thread = None
            self.start_lock = threading.Lock()
            self.directory_at = 0.0
            self.last_run = None

        # -- user mapping -----------------------------------------------------
        def taskbar_user(self, user_id):
            row = db.session.get(TaskbarUserLink, user_id)
            return row.taskbar_user_id if row else None

        def psa_user(self, taskbar_user_id, email=None):
            if not taskbar_user_id:
                return None
            taskbar_user_id = str(taskbar_user_id).lower()
            row = TaskbarUserLink.query.filter_by(taskbar_user_id=taskbar_user_id).first()
            if row:
                return row.user_id
            # Members who joined since the last directory refresh match by email.
            email = (email or '').strip().lower()
            user = User.query.filter(db.func.lower(User.email) == email).first() if email else None
            if user is None or db.session.get(TaskbarUserLink, user.id):
                return None
            db.session.add(TaskbarUserLink(user_id=user.id, taskbar_user_id=taskbar_user_id))
            return user.id

        def refresh_directory(self):
            members = self.client.directory()
            by_email = {}
            for member in members:
                email = (member.get('email') or '').strip().lower()
                if email and member.get('user_id'):
                    by_email[email] = str(member['user_id']).lower()
            users = User.query.filter(User.email.isnot(None)).all()
            wanted = {u.id: by_email[u.email.strip().lower()] for u in users if u.email.strip().lower() in by_email}
            for row in TaskbarUserLink.query.all():
                if wanted.get(row.user_id) != row.taskbar_user_id:
                    db.session.delete(row)
            db.session.flush()
            for user_id, taskbar_id in wanted.items():
                if not db.session.get(TaskbarUserLink, user_id):
                    db.session.add(TaskbarUserLink(user_id=user_id, taskbar_user_id=taskbar_id))
            db.session.commit()
            self.directory_at = time.time()
            return len(wanted)

        # -- PSA to Taskbar -----------------------------------------------------
        def payload(self, task, link, creating):
            due = task.due_at or default_due(task)
            body = {
                'title': taskbar_title(task.title),
                'due_at': iso_z(due),
                'priority': to_taskbar_priority(task.priority, link.taskbar_priority),
                'status': to_taskbar_status(task.status, link.taskbar_status),
                'assignee': self.taskbar_user(task.user_id),
            }
            if creating:
                school = f'School: {task.school.school_name}\n' if task.school else ''
                body.update(program_id=self.config.program_id, time_zone=self.config.time_zone,
                            description=f'{school}Synced from PSA Sales {marker(task.id)}')
            return body, task.due_at is None

        def record(self, link, remote, version, due_defaulted=None):
            link.taskbar_task_id = str(remote['id']).lower()
            link.taskbar_revision = int(remote['revision'])
            link.taskbar_status = remote.get('status')
            link.taskbar_priority = remote.get('priority')
            link.taskbar_updated_at = parse_remote_time(remote.get('updated_at'))
            link.psa_version = version
            if due_defaulted is not None:
                link.due_defaulted = due_defaulted
            link.state, link.attempts, link.next_attempt_at, link.last_error = 'synced', 0, None, None
            link.dirty_at = None
            link.last_synced_at = now()

        def find_existing(self, task):
            """Adopt a Taskbar copy left by an earlier attempt whose response was lost."""
            data = self.client.call('GET', '/tasks', params={'q': marker(task.id), 'program_id': self.config.program_id, 'limit': 5})
            for item in data.get('items', []):
                if marker(task.id) in (item.get('description') or ''):
                    return item
            return None

        def push(self, task, link):
            version = task.version
            if not link.taskbar_task_id:
                if not self.taskbar_user(task.user_id):
                    link.state, link.last_error, link.next_attempt_at = 'pending', 'Owner has no Taskbar account', now() + timedelta(minutes=10)
                    return 'unmapped'
                existing = self.find_existing(task)
                if existing:
                    self.record(link, existing, 0)
                else:
                    body, defaulted = self.payload(task, link, creating=True)
                    self.record(link, self.client.call('POST', '/tasks', body), version, defaulted)
                    return 'created'
            body, defaulted = self.payload(task, link, creating=False)
            for _ in range(2):
                try:
                    self.record(link, self.client.call('PATCH', f'/tasks/{link.taskbar_task_id}',
                                                       dict(body, revision=link.taskbar_revision)), version, defaulted)
                    return 'updated'
                except TaskbarError as exc:
                    if exc.status != 409:
                        raise
                remote = self.client.call('GET', f'/tasks/{link.taskbar_task_id}')
                remote_at = parse_remote_time(remote.get('updated_at'))
                if remote_at and link.dirty_at and remote_at > link.dirty_at:
                    self.apply_remote(link, remote, None)
                    return 'conflict_remote_won'
                link.taskbar_revision = int(remote['revision'])
            raise TaskbarError(409, 'Task kept changing in Taskbar')

        def fail(self, link, exc):
            link.attempts += 1
            delay = 60 if exc.status == 429 else min(1800, 30 * 2 ** min(link.attempts, 6))
            if exc.status == 404:
                link.state = 'detached'  # deleted in Taskbar or the program became inaccessible
            else:
                link.state = 'error'
            link.next_attempt_at = now() + timedelta(seconds=delay)
            link.last_error = str(exc)[:300]

        def pending_ids(self, limit):
            moment = now()
            query = (db.session.query(SalesTask.id)
                     .outerjoin(SalesTaskLink, SalesTaskLink.sales_task_id == SalesTask.id)
                     .filter(or_(SalesTaskLink.sales_task_id.is_(None),
                                 (SalesTask.version > SalesTaskLink.psa_version) & (SalesTaskLink.state != 'detached')))
                     .filter(or_(SalesTaskLink.next_attempt_at.is_(None), SalesTaskLink.next_attempt_at <= moment))
                     # Never backfill historic completed tasks that were never linked.
                     .filter(or_(SalesTaskLink.sales_task_id.isnot(None), SalesTask.status == 'open'))
                     .order_by(SalesTask.id).limit(limit))
            return [row[0] for row in query.all()]

        def run_once(self, limit=25):
            if not self.config.enabled:
                return {'skipped': 'disabled'}
            lock = None
            if db.engine.dialect.name == 'postgresql':
                lock = db.engine.connect()
                if not lock.execute(text('SELECT pg_try_advisory_lock(:k)'), {'k': LOCK_KEY}).scalar():
                    lock.close()
                    return {'skipped': 'locked'}
            counts = {}
            try:
                if time.time() - self.directory_at > 600:
                    try:
                        self.refresh_directory()
                    except TaskbarError as exc:
                        db.session.rollback()
                        log.warning('Taskbar directory refresh failed: %s', exc)
                for task_id in self.pending_ids(limit):
                    result = self.push_one(task_id)
                    counts[result] = counts.get(result, 0) + 1
                    if result == 'rate_limited':
                        break
            finally:
                if lock is not None:
                    lock.execute(text('SELECT pg_advisory_unlock(:k)'), {'k': LOCK_KEY})
                    lock.close()
            self.last_run = {'at': iso_z(now()), 'counts': counts}
            return counts

        def push_one(self, task_id):
            link = db.session.get(SalesTaskLink, task_id)
            if link is None:
                db.session.add(SalesTaskLink(sales_task_id=task_id, psa_version=0))
                db.session.commit()
            # Lock only the link row: reps saving the task itself are never blocked by Taskbar latency.
            link = SalesTaskLink.query.filter_by(sales_task_id=task_id).with_for_update().one()
            task = db.session.get(SalesTask, task_id)
            if link.state == 'detached' or task.version <= link.psa_version:
                db.session.commit()
                return 'current'
            if link.dirty_at is None:
                link.dirty_at = now()
            try:
                result = self.push(task, link)
            except TaskbarError as exc:
                self.fail(link, exc)
                result = 'rate_limited' if exc.status == 429 else 'error'
                log.warning('Taskbar push for sales task %s failed: %s', task_id, exc)
            db.session.commit()
            return result

        # -- Taskbar to PSA -----------------------------------------------------
        def apply_remote(self, link, remote, assignee_email):
            """Copy a Taskbar snapshot onto the linked PSA task. Caller holds the link lock."""
            task = link.task
            changed = False
            if (remote.get('title') or '').strip() and remote['title'].strip() != taskbar_title(task.title):
                task.title, changed = remote['title'].strip()[:PSA_TITLE_MAX], True
            remote_due = parse_remote_time(remote.get('due_at'))
            if remote_due and not (link.due_defaulted and remote_due == default_due(task)) and remote_due != task.due_at:
                task.due_at, link.due_defaulted, changed = remote_due, False, True
            if remote.get('priority') and to_psa_priority(remote['priority']) != task.priority:
                task.priority, changed = to_psa_priority(remote['priority']), True
            revert = False
            owner = self.psa_user(remote.get('assignee'), assignee_email)
            if owner and owner != task.user_id:
                if task.school and task.school.user_id != owner:
                    revert = True  # PSA keeps open tasks with the school's owner
                else:
                    task.user_id, changed = owner, True
            status = to_psa_status(remote.get('status'))
            if remote.get('status') and status != task.status:
                if status == 'open' and task.school and task.school.user_id != task.user_id:
                    revert = True
                else:
                    task.status, changed = status, True
                    task.completed_at = (parse_remote_time(remote.get('updated_at')) or now()) if status == 'completed' else None
            if changed:
                task.version += 1
            self.record(link, remote, 0 if revert else task.version)
            if revert:
                link.last_error = 'Taskbar change conflicted with school ownership; restored PSA values'
            return 'applied' if changed else 'unchanged'

        def handle_event(self, payload):
            remote = payload.get('task') if isinstance(payload, dict) else None
            if not isinstance(remote, dict) or not remote.get('id'):
                return 400, {'error': 'Task snapshot required'}
            remote_id = str(remote['id']).lower()
            link = SalesTaskLink.query.filter_by(taskbar_task_id=remote_id).with_for_update().first()
            if link is None:
                found = MARKER.search(remote.get('description') or '')
                if found:
                    # Our own create can echo back before its response is stored; wait on that row.
                    link = SalesTaskLink.query.filter_by(sales_task_id=int(found.group(1))).with_for_update().first()
                    if link is None or (link.taskbar_task_id and link.taskbar_task_id != remote_id):
                        return 200, {'result': 'ignored_unknown'}
            deleted = payload.get('event') == 'task.deleted' or str(remote.get('program_id') or '').lower() != self.config.program_id
            if deleted:
                if link:
                    link.state, link.last_error = 'detached', 'Removed from the Taskbar Sales program'
                    db.session.commit()
                return 200, {'result': 'detached' if link else 'ignored'}
            try:
                revision = int(remote['revision'])
            except (KeyError, TypeError, ValueError):
                return 400, {'error': 'revision required'}
            if link is None:
                return self.create_from_remote(remote, payload.get('assignee_email'))
            if link.state == 'detached':
                db.session.commit()
                return 200, {'result': 'ignored_detached'}
            if link.taskbar_revision is not None and revision <= link.taskbar_revision:
                db.session.commit()
                return 200, {'result': 'ignored_echo'}
            task = link.task
            remote_at = parse_remote_time(remote.get('updated_at'))
            if task.version > link.psa_version and link.dirty_at and remote_at and remote_at <= link.dirty_at:
                # The PSA edit is newer: remember Taskbar's revision so the next push overwrites it.
                link.taskbar_revision = revision
                link.taskbar_status, link.taskbar_priority = remote.get('status'), remote.get('priority')
                link.taskbar_task_id = remote_id
                db.session.commit()
                self.wake()
                return 200, {'result': 'conflict_local_won'}
            result = self.apply_remote(link, remote, payload.get('assignee_email'))
            db.session.commit()
            if link.psa_version == 0:
                self.wake()
            return 200, {'result': result}

        def create_from_remote(self, remote, assignee_email=None):
            owner = self.psa_user(remote.get('assignee'), assignee_email)
            if owner is None:
                db.session.commit()
                return 200, {'result': 'ignored_unmapped'}
            title = (remote.get('title') or '').strip()[:PSA_TITLE_MAX] or 'Taskbar task'
            status = to_psa_status(remote.get('status'))
            task = SalesTask(title=title, user_id=owner, due_at=parse_remote_time(remote.get('due_at')),
                             priority=to_psa_priority(remote.get('priority')), status=status,
                             completed_at=now() if status == 'completed' else None)
            db.session.add(task)
            db.session.flush()
            link = SalesTaskLink(sales_task_id=task.id, origin='taskbar', psa_version=0)
            db.session.add(link)
            self.record(link, remote, task.version)
            db.session.commit()
            return 201, {'result': 'created', 'sales_task_id': task.id}

        # -- worker --------------------------------------------------------------
        def wake(self):
            if self.config.enabled:
                self.ensure_started()
                self.wakeup.set()

        def ensure_started(self):
            if self.thread or not self.config.enabled or app.config.get('TESTING') or os.getenv('TASKBAR_SYNC_WORKER', 'true').lower() != 'true':
                return
            with self.start_lock:
                if not self.thread:
                    self.thread = threading.Thread(target=self.loop, name='taskbar-sync', daemon=True)
                    self.thread.start()

        def loop(self):
            while True:
                self.wakeup.wait(self.config.poll_seconds)
                self.wakeup.clear()
                time.sleep(1)  # coalesce bursts of saves
                with app.app_context():
                    try:
                        self.run_once()
                    except Exception:
                        log.exception('Taskbar sync run failed')
                        db.session.remove()

    sync = Sync()
    app.extensions['taskbar_sync'] = sync

    @event.listens_for(db.session, 'after_flush')
    def _note_task_writes(session, _context):
        if any(isinstance(obj, SalesTask) for obj in list(session.new) + list(session.dirty)):
            session.info['taskbar_sync_wake'] = True

    @event.listens_for(db.session, 'do_orm_execute')
    def _note_bulk_task_writes(state):
        if (state.is_update or state.is_insert) and state.bind_mapper is not None and state.bind_mapper.class_ is SalesTask:
            state.session.info['taskbar_sync_wake'] = True

    @event.listens_for(db.session, 'after_commit')
    def _wake_after_commit(session):
        if session.info.pop('taskbar_sync_wake', False):
            sync.wake()

    @app.before_request
    def _start_taskbar_worker():
        sync.ensure_started()

    @app.post('/api/integrations/taskbar/webhook')
    def taskbar_webhook():
        if not sync.config.enabled:
            return jsonify(error='Taskbar sync is not enabled'), 503
        body = request.get_data(cache=False)
        if len(body) > MAX_WEBHOOK_BYTES:
            return jsonify(error='Request too large'), 413
        if not verify_signature(sync.config.secret, request.headers.get('X-PSA-Sync-Timestamp'),
                                request.headers.get('X-PSA-Sync-Signature'), body):
            return jsonify(error='Invalid signature'), 401
        try:
            payload = json.loads(body)
        except ValueError:
            return jsonify(error='Invalid JSON'), 400
        try:
            status, result = sync.handle_event(payload)
        except Exception:
            db.session.rollback()
            log.exception('Taskbar webhook failed')
            return jsonify(error='Sync temporarily unavailable'), 503
        return jsonify(result), status

    @app.get('/api/integrations/taskbar/status')
    @jwt_required()
    def taskbar_status():
        user = db.session.get(User, int(get_jwt_identity()))
        if not user or not user.admin:
            return jsonify(error='Administrator access required'), 403
        states = dict(db.session.query(SalesTaskLink.state, db.func.count()).group_by(SalesTaskLink.state).all())
        errors = [{'sales_task_id': row.sales_task_id, 'state': row.state, 'error': row.last_error}
                  for row in SalesTaskLink.query.filter(SalesTaskLink.last_error.isnot(None)).limit(20)]
        return jsonify(enabled=sync.config.enabled, links=states, mapped_users=TaskbarUserLink.query.count(),
                       last_run=sync.last_run, recent_errors=errors)

    return sync
