"""Reviewed duplicate detection and conservative, history-preserving merges."""
import hashlib
import json
import re
from datetime import datetime,timezone
from difflib import SequenceMatcher
from flask import jsonify,request
from flask_jwt_extended import jwt_required,get_jwt_identity
from itsdangerous import URLSafeTimedSerializer,BadSignature,SignatureExpired
from sqlalchemy import delete,or_,update


def register_record_quality(app,db,svc):
    School=svc.SalesSchool
    signer=URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'],salt='psa-record-merge-v1')
    def user():return db.session.get(svc.User,int(get_jwt_identity()))
    def visible(sid,u):
        q=School.query.filter_by(id=sid)
        if not u.admin:q=q.filter_by(user_id=u.id)
        return q.first()
    def norm(v):return re.sub(r'[^a-z0-9]','',(v or '').casefold())
    def child_tables():
        for table in db.metadata.sorted_tables:
            for fk in table.foreign_keys:
                if fk.column.table.name=='sales_schools':yield table,fk.parent
    def snapshot(rows):
        values={str(s.id):{c.name:getattr(s,c.name) for c in School.__table__.columns} for s in rows}
        for table,col in child_tables():
            records=db.session.execute(table.select().where(col.in_([s.id for s in rows])).order_by(*table.primary_key.columns)).mappings().all()
            values[table.name]=[dict(row) for row in records]
        return values
    def digest(rows):return hashlib.sha256(json.dumps(snapshot(rows),sort_keys=True,default=str).encode()).hexdigest()
    def blockers(source,target):
        reasons=[]
        if source.user_id!=target.user_id:reasons.append('Assign both profiles to the same owner before merging.')
        if source.status!=target.status:reasons.append('Review and match the two pipeline stages before merging.')
        if any(getattr(source,k) is not None and getattr(source,k)!=getattr(target,k) for k in ('deal_value','sponsorship_value')):reasons.append('Review and match sponsorship or legacy deal values before merging.')
        ids=[source.id,target.id]
        if svc.OutreachRecipient.query.filter(svc.OutreachRecipient.school_id.in_(ids),svc.OutreachRecipient.status.in_(('queued','sending','unconfirmed'))).first():reasons.append('Resolve queued or uncertain outreach before merging.')
        if svc.SequenceEnrollment.query.filter(svc.SequenceEnrollment.school_id.in_(ids),svc.SequenceEnrollment.status=='active').first():reasons.append('Stop active follow-up enrollments before merging.')
        for plan in svc.CampaignPlan.query.filter(svc.CampaignPlan.status.notin_(('cancelled','expired','completed'))):
            if set(ids)&set(json.loads(plan.settings).get('school_ids',[])):reasons.append('Cancel or finish campaign plans referencing these records before merging.');break
        for draft in svc.AgentOutreachDraft.query.filter(svc.AgentOutreachDraft.status.notin_(('revoked','expired','executed'))):
            if set(ids)&set(json.loads(draft.settings).get('school_ids',[])):reasons.append('Revoke pending AI outreach requests before merging.');break
        for name in ('commission_splits','program_commissions'):
            table=db.metadata.tables[name]
            if db.session.execute(table.select().where(table.c.sales_school_id==source.id).limit(1)).first():reasons.append('Review source financial records before merging; they cannot be merged automatically.')
        return reasons
    @app.get('/api/crm/schools/<int:sid>/duplicates')
    @jwt_required()
    def record_duplicates(sid):
        u=user();row=visible(sid,u) if u else None
        if not row:return jsonify(error='Record not found'),404
        # Bounded candidate query; a common mailbox alone is a warning, never a merge decision.
        q=School.query.filter(School.id!=sid)
        if not u.admin:q=q.filter_by(user_id=u.id)
        terms=[db.func.lower(School.school_name).contains((row.school_name or '').split(' ')[0].lower(),autoescape=True)]
        if row.email:terms.append(db.func.lower(School.email)==row.email.lower())
        if row.address:terms.append(db.func.lower(School.address)==row.address.lower())
        found=[]
        for candidate in q.filter(or_(*terms)).order_by(School.id).limit(200):
            reasons=[]
            if norm(row.school_name)==norm(candidate.school_name):reasons.append('Same name')
            elif SequenceMatcher(None,norm(row.school_name),norm(candidate.school_name)).ratio()>=.88:reasons.append('Similar name')
            if row.email and row.email.casefold()==(candidate.email or '').casefold():reasons.append('Shared primary email; may be a sister school')
            if row.address and norm(row.address)==norm(candidate.address):reasons.append('Same address')
            if reasons:found.append(dict(id=candidate.id,name=candidate.school_name,address=candidate.address,owner=candidate.user_id,reasons=reasons))
        return jsonify(items=found[:20],can_merge=bool(u.admin))
    def merge_records(commit=False):
        u=user()
        if not u or not u.admin:return jsonify(error='Administrator access required'),403
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)-{'source_id','target_id','review_token'} or any(type(data.get(k)) is not int for k in ('source_id','target_id')) or data['source_id']==data['target_id']:return jsonify(error='Choose two different records in this workspace'),400
        svc.contact_write_lock()
        rows=School.query.filter(School.id.in_([data['source_id'],data['target_id']])).order_by(School.id).populate_existing().with_for_update().all()
        if len(rows)!=2:return jsonify(error='Record not found in this workspace'),404
        by_id={r.id:r for r in rows};source,target=by_id[data['source_id']],by_id[data['target_id']]
        blocked=blockers(source,target)
        if blocked:return jsonify(error='Resolve merge blockers first',blockers=blocked),409
        stamp=digest(rows)
        if not commit:
            return jsonify(source=dict(id=source.id,name=source.school_name),target=dict(id=target.id,name=target.school_name),retained_owner=target.user_id,retained_stage=target.status,warning='The source profile is removed. Its history, contacts and tasks move to the retained profile. Target details win conflicts; blank details are filled from the source. Original source details remain in audit history.',review_token=signer.dumps(dict(actor=u.id,source=source.id,target=target.id,stamp=stamp)))
        try:review=signer.loads(data.get('review_token',''),max_age=900)
        except (BadSignature,SignatureExpired):return jsonify(error='Merge review expired; preview again'),409
        if review!=dict(actor=u.id,source=source.id,target=target.id,stamp=stamp):return jsonify(error='Records changed; preview again'),409
        audit=json.dumps(snapshot([source]),default=str)
        target_links={l.contact_id:l for l in svc.SchoolContact.query.filter_by(school_id=target.id)}
        for link in svc.SchoolContact.query.filter_by(school_id=source.id).all():
            existing=target_links.get(link.contact_id)
            if existing:
                existing.roles_json=json.dumps(sorted(set(json.loads(existing.roles_json))|set(json.loads(link.roles_json))))
                existing.tags_json=json.dumps(sorted(set(json.loads(existing.tags_json))|set(json.loads(link.tags_json))))
                existing.do_not_contact=existing.do_not_contact or link.do_not_contact
                if link.suppression_reason and link.suppression_reason not in existing.suppression_reason:existing.suppression_reason=(existing.suppression_reason+'; '+link.suppression_reason).strip('; ')[:500]
                existing.version+=1
                svc.OutreachRecipient.query.filter_by(contact_link_id=link.id).update({'contact_link_id':existing.id})
                db.session.delete(link)
            else:
                link.school_id=target.id;link.is_primary=False;link.version+=1
        db.session.flush()
        for table,col in child_tables():
            if table.name=='school_contacts':continue
            values={col.name:target.id}
            if table.name=='sales_tasks':values['version']=table.c.version+1
            db.session.execute(update(table).where(col==source.id).values(**values))
        emails=list(dict.fromkeys(e for e in target.get_all_emails()+source.get_all_emails() if e))
        if not target.email and emails:target.email=emails[0]
        target.set_additional_emails(emails)
        for field in ('contact_name','phone','address','county','website','industry','next_action','next_action_at','closed_at','closed_by_id'):
            if not getattr(target,field) and getattr(source,field):setattr(target,field,getattr(source,field))
        if not target.lat and source.lat and norm(target.address)==norm(source.address):target.lat,target.lng=source.lat,source.lng
        target.notes=(target.notes or '')+('\n\nMerged notes from '+source.school_name+':\n'+source.notes if source.notes else '')
        db.session.add(svc.SchoolActivity(sales_school_id=target.id,actor_id=u.id,kind='note',detail='Merged source profile '+str(source.id)+'. Original details and linked records: '+audit))
        db.session.flush()
        db.session.execute(delete(School).where(School.id==source.id).execution_options(synchronize_session=False))
        source_id,target_id=source.id,target.id
        db.session.commit()
        return jsonify(id=target_id,merged_id=source_id)

    @app.post('/api/crm/schools/merge/preview')
    @jwt_required()
    def preview_record_merge():return merge_records(False)

    @app.post('/api/crm/schools/merge/commit')
    @jwt_required()
    def commit_record_merge():return merge_records(True)
