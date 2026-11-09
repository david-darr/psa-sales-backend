"""Explicit school ownership, reviewed reassignment, and atomic self-claims."""
import json
import uuid
from datetime import datetime, timedelta, timezone
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required


class OwnershipConflict(ValueError):
    pass


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def change_owners(db, schools, new_id, actor, Task, Activity, operation=None):
    """Caller locks schools in ID order. Batch SQL keeps large assignments bounded."""
    from sqlalchemy.orm.attributes import set_committed_value
    changed = [school for school in schools if school.user_id != new_id]
    ids = [school.id for school in changed]
    if not ids:
        return 0
    table = db.metadata.tables.get('outreach_recipients')
    if table is not None:
        recipients = db.session.execute(table.select().with_only_columns(table.c.id, table.c.status).where(
            table.c.school_id.in_(ids), table.c.status.in_(('queued', 'sending'))).order_by(table.c.id).with_for_update()).all()
        if any(row.status == 'sending' for row in recipients):
            raise OwnershipConflict('A selected school has an email in flight. Wait for it to finish before changing its owner.')
        db.session.execute(table.update().where(table.c.school_id.in_(ids), table.c.status == 'queued').values(
            status='cancelled', error='Owner changed. Prepare and review a new batch with the new owner.'))
    if new_id is not None:
        Task.query.filter(Task.school_id.in_(ids), Task.status == 'open').update(
            {Task.user_id: new_id, Task.version: Task.version + 1}, synchronize_session=False)
    model = type(changed[0])
    db.session.query(model).filter(model.id.in_(ids)).update(
        {model.user_id: new_id, model.ownership_version: model.ownership_version + 1}, synchronize_session=False)
    for school in changed:
        old_id = school.user_id
        set_committed_value(school, 'user_id', new_id)
        set_committed_value(school, 'ownership_version', (school.ownership_version or 0) + 1)
        db.session.expire(school, ['user'])
        db.session.add(Activity(sales_school_id=school.id, actor_id=actor.id, kind='ownership',
            detail=f'Owner changed from {old_id if old_id is not None else "unassigned"} to {new_id if new_id is not None else "unassigned"}' +
                   (f' (review {operation})' if operation else '')))
    return len(changed)


def change_owner(db, school, new_id, actor, Task, Activity, operation=None):
    return bool(change_owners(db, [school], new_id, actor, Task, Activity, operation))


def register_ownership_routes(app, db, User, School, Task, Activity, serialize, school_query):
    class AssignmentReview(db.Model):
        __tablename__ = 'school_assignment_reviews'
        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        actor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
        target_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'))
        selection = db.Column(db.Text, nullable=False)
        snapshot = db.Column(db.Text, nullable=False)
        expires_at = db.Column(db.DateTime, nullable=False, default=lambda: now() + timedelta(minutes=15))
        result = db.Column(db.Text)

    @app.errorhandler(OwnershipConflict)
    def conflict(error):
        db.session.rollback()
        return jsonify(error=str(error)), 409

    def actor():
        return db.session.get(User, int(get_jwt_identity()))

    def snapshot(rows):
        return json.dumps([[row.id, row.user_id, row.ownership_version, row.school_name, row.address, row.county, row.status]
                           for row in rows], ensure_ascii=False)

    def selected_query(selection, user):
        return School.query.filter(School.id.in_(selection['ids'])) if 'ids' in selection else school_query(user, selection['filters'])

    @app.post('/api/crm/schools/assignment-preview')
    @jwt_required()
    def assignment_preview():
        user = actor()
        if not user or not user.admin:
            return jsonify(error='Administrator access required'), 403
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or 'user_id' not in data or set(data) - {'user_id','ids','filters'} or ('ids' in data) == ('filters' in data):
            return jsonify(error='Supply a target user_id and either IDs or saved filters'), 400
        target = data['user_id']
        if target is not None and (type(target) is not int or not db.session.get(User, target)):
            return jsonify(error='Employee not found'), 400
        if 'ids' in data:
            ids = data['ids']
            if not isinstance(ids, list) or not 1 <= len(ids) <= 2000 or any(type(i) is not int or i < 1 for i in ids):
                return jsonify(error='Choose between 1 and 2,000 schools'), 400
            selection = {'ids': sorted(set(ids))}
        else:
            filters = data['filters']
            if not isinstance(filters, dict) or set(filters) - {'q','stage','type','owner','county','scope','due'} or any(not isinstance(value,str) for value in filters.values()):
                return jsonify(error='Invalid saved school filters'), 400
            selection = {'filters': filters}
        try:
            rows = selected_query(selection, user).order_by(School.id).limit(2001).all()
        except ValueError as error:
            return jsonify(error=str(error)), 400
        if not rows or len(rows) > 2000 or ('ids' in selection and len(rows) != len(selection['ids'])):
            return jsonify(error='Choose a filter matching between 1 and 2,000 available schools'), 400
        selection['target_id'] = target
        review = AssignmentReview(actor_id=user.id, target_id=target, selection=json.dumps(selection), snapshot=snapshot(rows))
        db.session.add(review); db.session.commit()
        counties, owners = {}, {}
        for row in rows:
            county = row.county or 'Not recorded'; counties[county] = counties.get(county, 0) + 1
            owner = row.user.name if row.user else 'Unassigned'; owners[owner] = owners.get(owner, 0) + 1
        return jsonify(id=review.id, total=len(rows), changed=sum(row.user_id != target for row in rows),
            target_id=target, target_name=db.session.get(User,target).name if target is not None else 'Unassigned',
            expires_at=review.expires_at.isoformat()+'Z', counties=counties, owners=owners,
            sample=[{'id': row.id,'school_name':row.school_name,'owner_name':row.user.name if row.user else 'Unassigned','county':row.county or ''} for row in rows[:20]])

    @app.post('/api/crm/schools/assignment-reviews/<string:rid>/commit')
    @jwt_required()
    def assignment_commit(rid):
        user = actor()
        if not user or not user.admin:
            return jsonify(error='Administrator access required'), 403
        review = AssignmentReview.query.filter_by(id=rid,actor_id=user.id).with_for_update().first()
        if not review:
            return jsonify(error='Review not found'), 404
        if review.result:
            return jsonify(json.loads(review.result))
        if review.expires_at < now():
            return jsonify(error='This assignment review expired. Preview again.'), 409
        original_target = json.loads(review.selection).get('target_id')
        if original_target is not None and (review.target_id != original_target or not db.session.get(User, original_target)):
            return jsonify(error='The target employee is unavailable. Preview again.'), 409
        rows = selected_query(json.loads(review.selection),user).order_by(School.id).limit(2001).with_for_update().populate_existing().all()
        if snapshot(rows) != review.snapshot:
            return jsonify(error='The schools or their owners changed. Preview again.'), 409
        changed = change_owners(db,rows,review.target_id,user,Task,Activity,review.id)
        result = {'updated':changed, 'total':len(rows), 'review_id':review.id}
        review.result = json.dumps(result); db.session.commit()
        return jsonify(result)

    @app.post('/api/crm/schools/<int:sid>/claim')
    @jwt_required()
    def claim_school(sid):
        user = actor()
        if not user:
            return jsonify(error='User not found'), 404
        data = request.get_json(silent=True)
        if data not in (None, {}):
            return jsonify(error='The claimant is your signed-in account; do not supply an owner'), 400
        school = School.query.filter_by(id=sid).with_for_update().populate_existing().first()
        if not school:
            return jsonify(error='School not found'), 404
        if school.user_id not in (None,user.id):
            return jsonify(error='This school has already been claimed or assigned. Refresh the pool.'), 409
        changed = change_owner(db,school,user.id,user,Task,Activity)
        db.session.commit()
        return jsonify(school=serialize(school), claimed=changed)

    return AssignmentReview
