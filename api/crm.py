"""Bounded CRM queries and team workflows. All record access is scoped server-side."""

from datetime import datetime, timedelta, timezone

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import func, or_, and_
from sqlalchemy.orm import joinedload

from .portfolio import FINISHED_STAGES, STAGES, set_school_status


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_date(value):
    if value is None or value == '':
        return None
    if not isinstance(value, str):
        raise ValueError('Enter a valid due date')
    value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def calendar_today():
    """Due dates are calendar dates; use the viewer's local day when supplied."""
    value = request.args.get('today')
    if value:
        return datetime.strptime(value, '%Y-%m-%d')
    return now().replace(hour=0, minute=0, second=0, microsecond=0)


def register_crm_routes(app, db, User, School, SentEmail, Task, Activity, serialize_school, Directory):
    def current_user():
        return db.session.get(User, int(get_jwt_identity()))

    def scoped(query, model, user):
        if not user.admin or request.args.get('scope') == 'mine':
            query = query.filter(model.user_id == user.id)
        return query

    def page_args():
        try:
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 25))
        except (TypeError, ValueError):
            raise ValueError('Page and limit must be integers')
        if page < 1 or limit < 1 or limit > 100:
            raise ValueError('Use a positive page and a limit between 1 and 100')
        return page, limit

    def school_query(user):
        query = scoped(School.query, School, user)
        stage = request.args.get('stage')
        if stage:
            wanted = [item.strip() for item in stage.split(',') if item.strip()]
            if not wanted or any(item not in STAGES for item in wanted):
                raise ValueError('Invalid school stage')
            query = query.filter(School.status.in_(wanted))
        owner = request.args.get('owner')
        if owner:
            try:
                query = query.filter(School.user_id == int(owner))
            except ValueError:
                raise ValueError('Invalid owner')
        kind = request.args.get('type')
        if kind:
            if kind not in ('preschool', 'elementary', 'private'):
                raise ValueError('Invalid school type')
            query = query.filter(School.school_type == kind)
        term = request.args.get('q', '').strip().lower()[:120]
        if term:
            query = query.filter(or_(*[
                func.lower(field).contains(term, autoescape=True)
                for field in (School.school_name, School.contact_name, School.email, School.address)
            ]))
        due = request.args.get('due')
        today = calendar_today()
        if due == 'overdue':
            query = query.filter(School.next_action_at < today, School.next_action.isnot(None), School.next_action != '')
        elif due == 'today':
            query = query.filter(School.next_action_at >= today, School.next_action_at < today + timedelta(days=1))
        elif due == 'none':
            query = query.filter(or_(School.next_action.is_(None), School.next_action == ''))
        elif due:
            raise ValueError('Invalid action filter')
        return query

    def task_dict(task):
        return {
            'id': task.id, 'title': task.title, 'user_id': task.user_id,
            'owner_name': task.owner.name, 'school_id': task.school_id,
            'school_name': task.school.school_name if task.school else None,
            'due_at': task.due_at.isoformat() if task.due_at else None,
            'priority': task.priority, 'status': task.status, 'version': task.version,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
        }

    @app.patch('/api/crm/profile')
    @jwt_required()
    def crm_profile():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not data or any(key not in ('name', 'phone') for key in data):
            return jsonify(error='Supply your name or phone number'), 400
        if 'name' in data and (not isinstance(data['name'], str) or not 1 <= len(data['name'].strip()) <= 120):
            return jsonify(error='Enter a name under 120 characters'), 400
        if 'phone' in data and (not isinstance(data['phone'], str) or len(data['phone']) > 50):
            return jsonify(error='Enter a phone number under 50 characters'), 400
        for key in data:
            setattr(user, key, data[key].strip())
        db.session.commit()
        return jsonify(id=user.id, name=user.name, phone=user.phone, email=user.email,
                       admin=user.admin, mail_connected=bool(user.email_password))

    @app.get('/api/crm/schools')
    @jwt_required()
    def crm_schools():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        try:
            page, limit = page_args()
            query = school_query(user)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        sort = request.args.get('sort', 'name')
        order = {'name': School.school_name.asc(), 'newest': School.created_at.desc(),
                 'due': School.next_action_at.asc().nullslast(),
                 'closed': School.closed_at.desc().nullslast()}.get(sort)
        if order is None:
            return jsonify(error='Invalid sort'), 400
        total = query.count()
        rows = query.options(joinedload(School.user), joinedload(School.closed_by)).order_by(order, School.id).offset((page - 1) * limit).limit(limit).all()
        return jsonify(items=[serialize_school(row) for row in rows], total=total, page=page, limit=limit)

    @app.get('/api/crm/directory')
    @jwt_required()
    def crm_directory():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        try:
            page, limit = page_args()
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        query = Directory.query
        term = request.args.get('q', '').strip().lower()[:120]
        if term:
            query = query.filter(or_(*[func.lower(field).contains(term, autoescape=True)
                for field in (Directory.name, Directory.address, Directory.contact, Directory.email)]))
        total = query.count()
        assignment_id = db.session.query(func.min(School.id)).filter(or_(
            and_(Directory.email != '', or_(
                func.lower(func.trim(School.email)) == func.lower(func.trim(Directory.email)),
                func.lower(School.additional_emails).contains('"' + func.lower(func.trim(Directory.email)) + '"'))),
            and_(Directory.address != '', func.lower(func.trim(School.school_name)) == func.lower(func.trim(Directory.name)),
                 func.lower(func.trim(School.address)) == func.lower(func.trim(Directory.address))),
        )).correlate(Directory).scalar_subquery()
        rows = query.outerjoin(School, School.id == assignment_id).outerjoin(User, User.id == School.user_id).with_entities(
            Directory, School.id, School.user_id, User.name).order_by(Directory.name, Directory.id).offset((page - 1) * limit).limit(limit).all()
        return jsonify(items=[{'id': item.id, 'name': item.name, 'email': item.email,
            'address': item.address, 'phone': item.phone, 'contact': item.contact,
            'assigned': assignment is not None, 'owner_name': owner_name,
            'sales_school_id': assignment if user.admin or owner_id == user.id else None,
        } for item, assignment, owner_id, owner_name in rows], total=total, page=page, limit=limit)

    @app.post('/api/crm/schools/bulk')
    @jwt_required()
    def crm_bulk_schools():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or any(key not in ('ids', 'status', 'user_id') for key in data):
            return jsonify(error='Supply school IDs and a stage or owner'), 400
        ids = data.get('ids')
        if (not isinstance(ids, list) or not ids or len(ids) > 100
                or any(type(item) is not int or item < 1 for item in ids)):
            return jsonify(error='Select between 1 and 100 schools'), 400
        if 'status' not in data and 'user_id' not in data:
            return jsonify(error='Choose a stage or owner'), 400
        if 'status' in data and data['status'] not in STAGES:
            return jsonify(error='Invalid school stage'), 400
        owner = None
        if 'user_id' in data:
            if not user.admin:
                return jsonify(error='Only administrators can reassign schools'), 403
            if type(data['user_id']) is not int:
                return jsonify(error='Invalid employee'), 400
            owner = db.session.get(User, data['user_id'])
            if not owner:
                return jsonify(error='Employee not found'), 400
        rows = School.query.filter(School.id.in_(set(ids))).order_by(School.id).with_for_update().all()
        # Reject the entire operation if even one record is absent or inaccessible.
        if len(rows) != len(set(ids)) or any(not user.admin and row.user_id != user.id for row in rows):
            return jsonify(error='One or more schools are unavailable'), 404
        changed = 0
        for row in rows:
            changes = []
            if 'status' in data and row.status != data['status']:
                set_school_status(row, data['status'], user.id)
                changes.append('stage to ' + data['status'].replace('_', ' '))
            if owner and row.user_id != owner.id:
                row.user_id = owner.id
                Task.query.filter_by(school_id=row.id, status='open').update(
                    {Task.user_id: owner.id, Task.version: Task.version + 1}, synchronize_session=False)
                changes.append('owner to ' + owner.name)
            if changes:
                db.session.add(Activity(sales_school_id=row.id, actor_id=user.id, kind='updated',
                                        detail='Updated ' + ', '.join(changes)))
                changed += 1
        db.session.commit()
        return jsonify(updated=changed)

    @app.route('/api/crm/tasks', methods=['GET', 'POST'])
    @jwt_required()
    def crm_tasks():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        if request.method == 'GET':
            try:
                page, limit = page_args()
                today = calendar_today()
            except ValueError as exc:
                return jsonify(error=str(exc)), 400
            query = scoped(Task.query, Task, user)
            school_id = request.args.get('school_id', type=int)
            if school_id:
                school = db.session.get(School, school_id)
                if not school or (not user.admin and school.user_id != user.id):
                    return jsonify(error='School not found'), 404
                query = query.filter(Task.school_id == school_id)
            view = request.args.get('view', 'open')
            if view == 'completed':
                query = query.filter(Task.status == 'completed')
            elif view in ('open', 'today', 'overdue', 'upcoming'):
                query = query.filter(Task.status == 'open')
                if view == 'today':
                    query = query.filter(Task.due_at >= today, Task.due_at < today + timedelta(days=1))
                elif view == 'overdue':
                    query = query.filter(Task.due_at < today)
                elif view == 'upcoming':
                    query = query.filter(Task.due_at >= today + timedelta(days=1))
            else:
                return jsonify(error='Invalid task view'), 400
            total = query.count()
            rows = query.options(joinedload(Task.owner), joinedload(Task.school)).order_by(
                Task.due_at.asc().nullslast(), Task.id).offset((page - 1) * limit).limit(limit).all()
            return jsonify(items=[task_dict(row) for row in rows], total=total, page=page, limit=limit)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='Supply a task'), 400
        title = data.get('title')
        if not isinstance(title, str) or not title.strip() or len(title.strip()) > 240:
            return jsonify(error='Enter a task title under 240 characters'), 400
        owner_id = data.get('user_id', user.id)
        if type(owner_id) is not int or not db.session.get(User, owner_id):
            return jsonify(error='Employee not found'), 400
        if owner_id != user.id and not user.admin:
            return jsonify(error='Only administrators can assign tasks to teammates'), 403
        school_id = data.get('school_id') or None
        if school_id is not None:
            if type(school_id) is not int:
                return jsonify(error='Invalid school'), 400
            school = db.session.get(School, school_id)
            if not school or (not user.admin and school.user_id != user.id):
                return jsonify(error='School not found'), 404
            if school.user_id != owner_id:
                return jsonify(error='Assign the task to this school’s owner'), 400
        if data.get('priority', 'normal') not in ('normal', 'high'):
            return jsonify(error='Invalid priority'), 400
        try:
            due_at = parse_date(data.get('due_at'))
        except ValueError:
            return jsonify(error='Enter a valid due date'), 400
        task = Task(title=title.strip(), user_id=owner_id, school_id=school_id, due_at=due_at,
                    priority=data.get('priority', 'normal'))
        db.session.add(task)
        db.session.commit()
        return jsonify(task_dict(task)), 201

    @app.patch('/api/crm/tasks/<int:task_id>')
    @jwt_required()
    def crm_update_task(task_id):
        user = current_user()
        task = Task.query.filter_by(id=task_id).with_for_update().first()
        if not user or not task or (not user.admin and task.user_id != user.id):
            return jsonify(error='Task not found'), 404
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or any(key not in ('version', 'status', 'due_at') for key in data):
            return jsonify(error='Supply a task status or due date'), 400
        if type(data.get('version')) is not int or data['version'] != task.version:
            return jsonify(error='This task changed. Refresh before trying again.'), 409
        if 'status' not in data and 'due_at' not in data:
            return jsonify(error='Supply a task status or due date'), 400
        if 'status' in data:
            if data['status'] not in ('open', 'completed'):
                return jsonify(error='Invalid task status'), 400
            if data['status'] == 'open' and task.school and task.school.user_id != task.user_id:
                return jsonify(error='This school changed owner. Create a new task for its current owner.'), 409
            task.status = data['status']
            task.completed_at = now() if task.status == 'completed' else None
        if 'due_at' in data:
            try:
                task.due_at = parse_date(data['due_at'])
            except ValueError:
                return jsonify(error='Enter a valid due date'), 400
        task.version += 1
        db.session.commit()
        return jsonify(task_dict(task))

    @app.get('/api/crm/overview')
    @jwt_required()
    def crm_overview():
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        try:
            today = calendar_today()
        except ValueError:
            return jsonify(error='Enter a valid local date'), 400
        schools = scoped(School.query, School, user)
        emails = scoped(SentEmail.query, SentEmail, user)
        tasks = scoped(Task.query, Task, user)
        pipeline = {stage: count for stage, count in schools.with_entities(School.status, func.count(School.id)).group_by(School.status).all()}
        sent_count = emails.count()
        responded = emails.filter(SentEmail.responded.is_(True)).count()
        finished = db.session.query(School.id).filter(School.status.in_(FINISHED_STAGES))
        due_followups = emails.filter(SentEmail.user_id == user.id, SentEmail.responded.is_(False),
            SentEmail.followup_sent.is_(False), SentEmail.sent_at <= now() - timedelta(days=7),
            SentEmail.sent_at >= now() - timedelta(days=90),
            or_(SentEmail.sales_school_id.is_(None), SentEmail.sales_school_id.notin_(finished))).count()
        chart_today = now().replace(hour=0, minute=0, second=0, microsecond=0)
        recent = emails.filter(SentEmail.sent_at >= chart_today - timedelta(days=13)).with_entities(
            func.date(SentEmail.sent_at), func.count(SentEmail.id)).group_by(func.date(SentEmail.sent_at)).all()
        by_day = {str(day): count for day, count in recent}
        trend = [{'date': (chart_today - timedelta(days=13 - index)).date().isoformat(),
                  'sent': by_day.get((chart_today - timedelta(days=13 - index)).date().isoformat(), 0)} for index in range(14)]
        task_rows = tasks.filter(Task.status == 'open').options(joinedload(Task.owner), joinedload(Task.school)).order_by(
            Task.due_at.asc().nullslast(), Task.id).limit(6).all()
        action_rows = schools.filter(School.next_action.isnot(None), School.next_action != '').options(
            joinedload(School.user)).order_by(School.next_action_at.asc().nullslast(), School.id).limit(5).all()
        activities = Activity.query.join(School, School.id == Activity.sales_school_id).join(User, User.id == Activity.actor_id)
        if not user.admin or request.args.get('scope') == 'mine':
            activities = activities.filter(School.user_id == user.id)
        activity_rows = activities.with_entities(Activity.kind, Activity.detail, Activity.created_at,
            School.id, School.school_name, User.name).order_by(Activity.created_at.desc(), Activity.id.desc()).limit(6).all()
        return jsonify(
            scope='team' if user.admin and request.args.get('scope') != 'mine' else 'mine',
            schools=sum(pipeline.values()), pipeline=pipeline, sent=sent_count, responses=responded,
            response_rate=round(100 * responded / sent_count, 1) if sent_count else 0,
            due_followups=due_followups,
            tasks_open=tasks.filter(Task.status == 'open').count(),
            tasks_overdue=tasks.filter(Task.status == 'open', Task.due_at < today).count(),
            tasks=[task_dict(row) for row in task_rows], actions=[serialize_school(row) for row in action_rows],
            trend=trend, activity=[{'kind': row[0], 'detail': row[1], 'at': row[2].isoformat(),
                'school_id': row[3], 'school_name': row[4], 'actor': row[5]} for row in activity_rows],
        )

    def team_rows(today, only_id=None):
        school_counts = db.session.query(School.user_id.label('uid'), func.count(School.id).label('count')).group_by(School.user_id).subquery()
        email_counts = db.session.query(SentEmail.user_id.label('uid'), func.count(SentEmail.id).label('count')).group_by(SentEmail.user_id).subquery()
        reply_counts = db.session.query(SentEmail.user_id.label('uid'), func.count(SentEmail.id).label('count')).filter(SentEmail.responded.is_(True)).group_by(SentEmail.user_id).subquery()
        overdue_counts = db.session.query(Task.user_id.label('uid'), func.count(Task.id).label('count')).filter(Task.status == 'open', Task.due_at < today).group_by(Task.user_id).subquery()
        query = db.session.query(User, school_counts.c.count, email_counts.c.count, reply_counts.c.count, overdue_counts.c.count).outerjoin(
            school_counts, school_counts.c.uid == User.id).outerjoin(email_counts, email_counts.c.uid == User.id).outerjoin(
            reply_counts, reply_counts.c.uid == User.id).outerjoin(overdue_counts, overdue_counts.c.uid == User.id)
        if only_id is not None:
            query = query.filter(User.id == only_id)
        rows = query.order_by(User.name).all()
        return [{'id': member.id, 'name': member.name, 'email': member.email,
            'role': 'Administrator' if member.admin else 'Sales representative', 'schools': schools or 0,
            'sent': sent or 0, 'responses': replies or 0, 'overdue': overdue or 0,
            'admin': bool(member.admin), 'mail_connected': bool(member.email_password)}
            for member, schools, sent, replies, overdue in rows]

    @app.get('/api/crm/team')
    @jwt_required()
    def crm_team():
        if not current_user():
            return jsonify(error='User not found'), 404
        try:
            today = calendar_today()
        except ValueError:
            return jsonify(error='Enter a valid local date'), 400
        return jsonify(team_rows(today))

    @app.patch('/api/crm/team/<int:member_id>')
    @jwt_required()
    def crm_update_team_member(member_id):
        user = current_user()
        if not user:
            return jsonify(error='User not found'), 404
        if not user.admin:
            return jsonify(error='Administrator access required'), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or set(data) != {'admin'} or type(data['admin']) is not bool:
            return jsonify(error='Supply admin as true or false'), 400
        member = User.query.filter_by(id=member_id).with_for_update().first()
        if not member:
            return jsonify(error='Team member not found'), 404
        if member.id == user.id:
            return jsonify(error='You cannot change your own administrator access'), 400
        if member.admin and not data['admin'] and User.query.filter(User.admin.is_(True)).count() <= 1:
            return jsonify(error='At least one administrator is required'), 400
        member.admin = data['admin']
        db.session.commit()
        return jsonify(team_rows(now().replace(hour=0, minute=0, second=0, microsecond=0), member.id)[0])
