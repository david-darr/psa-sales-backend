"""Agent preparation and execution of human-approved, sender-owned batches.

Agents never receive common send review tokens and cannot call approval routes.
All recipients and copy are frozen in the common contact review service.
"""
import json
import uuid
from datetime import timedelta
from flask import g, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required


def register_agent_workflows(app, db, svc, Key, route, delegate):
    from . import outreach as out

    class Draft(db.Model):
        __tablename__='agent_outreach_drafts'
        id=db.Column(db.String(36),primary_key=True)
        user_id=db.Column(db.Integer,db.ForeignKey('users.id'),nullable=False,index=True)
        key_id=db.Column(db.Integer,db.ForeignKey('agent_api_keys.id'),nullable=False,index=True)
        settings=db.Column(db.Text,nullable=False)
        preview=db.Column(db.Text,nullable=False)
        review_token=db.Column(db.String(100),nullable=False)
        revision=db.Column(db.Integer,nullable=False,default=1)
        status=db.Column(db.String(16),nullable=False,default='awaiting')
        created_at=db.Column(db.DateTime,nullable=False,default=svc.utc_now)
        expires_at=db.Column(db.DateTime,nullable=False)
        approval_id=db.Column(db.String(36))
        approved_by=db.Column(db.Integer,db.ForeignKey('users.id'))
        approved_at=db.Column(db.DateTime)
        batch_id=db.Column(db.Integer,db.ForeignKey('outreach_batches.id'),unique=True)
        executed_at=db.Column(db.DateTime)

    class Event(db.Model):
        __tablename__='agent_outreach_events'
        id=db.Column(db.Integer,primary_key=True)
        draft_id=db.Column(db.String(36),db.ForeignKey('agent_outreach_drafts.id'),nullable=False,index=True)
        key_id=db.Column(db.Integer,db.ForeignKey('agent_api_keys.id'),nullable=False)
        user_id=db.Column(db.Integer,db.ForeignKey('users.id'),nullable=False)
        event=db.Column(db.String(24),nullable=False)
        approval_id=db.Column(db.String(36))
        batch_id=db.Column(db.Integer,db.ForeignKey('outreach_batches.id'))
        created_at=db.Column(db.DateTime,nullable=False,default=svc.utc_now)

    svc.AgentOutreachDraft,svc.AgentOutreachEvent=Draft,Event
    def record(draft,event):
        db.session.add(Event(draft_id=draft.id,key_id=draft.key_id,user_id=draft.user_id,event=event,
            approval_id=draft.approval_id,batch_id=draft.batch_id))
    svc.record_agent_outreach_event=record
    def key_valid(key,uid,scope=None):
        return bool(key and key.user_id==uid and not key.revoked_at and key.expires_at>svc.utc_now()
            and (not scope or scope in key.scopes.split(',')))
    def public(draft,detail=True):
        key=db.session.get(Key,draft.key_id)
        result=dict(id=draft.id,key_id=draft.key_id,key_name=key.name if key else 'Unavailable key',sender_id=draft.user_id,
            status=draft.status,revision=draft.revision,created_at=out.iso(draft.created_at),expires_at=out.iso(draft.expires_at),
            approval_id=draft.approval_id,approved_by=draft.approved_by,approved_at=out.iso(draft.approved_at),batch_id=draft.batch_id,executed_at=out.iso(draft.executed_at),
            key_active=key_valid(key,draft.user_id),can_execute=key_valid(key,draft.user_id,'outreach:send'),approval_url='/emails?tab=approvals&draft='+draft.id)
        result['approval_instructions']='Review in Kairos PSA Command > Outreach > Agent requests. Human approval is required; the agent cannot approve itself. The PSA website is optional.'
        if detail:
            result.update(preview=json.loads(draft.preview),events=[dict(event=e.event,key_id=e.key_id,user_id=e.user_id,
                approval_id=e.approval_id,batch_id=e.batch_id,created_at=out.iso(e.created_at)) for e in Event.query.filter_by(draft_id=draft.id).order_by(Event.id.desc()).limit(50)])
        return result
    def stripped(payload):
        return {k:v for k,v in payload.items() if k!='preview_token'}
    def reviewed(user,settings):
        payload,status=delegate('email_preview',user,method='POST',body=settings)
        if status!=200:return None,(payload,status)
        return payload,None
    def sender():
        return db.session.get(svc.User,int(get_jwt_identity()))
    def own(did,user,lock=False):
        query=Draft.query.filter_by(id=did,user_id=user.id)
        return query.with_for_update().first() if lock else query.first()

    @route('/imports/preview',['POST'],'import_preview',required_scope='schools:import')
    def import_preview(user):
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)!={'rows'} or not isinstance(data['rows'],list) or not 1<=len(data['rows'])<=100:
            return dict(error='Supply 1 to 100 school/contact rows'),400
        return delegate('preview_import',user,method='POST',body=data)

    @route('/imports/<string:pid>/commit',['POST'],'import_commit',required_scope='schools:import')
    def import_commit(user,pid):
        return delegate('commit_import',user,method='POST',body=request.get_json(silent=True),view_args=dict(pid=pid))

    @route('/schools/<int:sid>/contacts',['GET'],'contacts')
    def contacts(user,sid):
        return delegate('school_contacts',user,view_args=dict(sid=sid))

    @route('/outreach/templates',['GET'],'templates',required_scope='outreach:read')
    def templates(user):
        return delegate('template_list',user)

    @route('/outreach/attachments',['GET'],'attachments',required_scope='outreach:read')
    def attachments(user):
        return delegate('template_assets',user)

    @route('/outreach/check-replies',['POST'],'check_replies',required_scope='outreach:prepare')
    def check_replies(user):
        if request.get_json(silent=True) not in ({},None):return dict(error='No sender or mailbox arguments accepted'),400
        svc.sync_user_mailbox(user)
        return svc.mail_sync_status(user.id),200

    @route('/outreach/replies',['GET'],'replies',required_scope='outreach:read')
    def replies(user):
        return reply_list(user)

    @route('/outreach/<int:batch_id>/cancel',['POST'],'cancel_outreach',required_scope='outreach:send')
    def cancel_outreach(user,batch_id):
        if request.get_json(silent=True) not in ({},None):return dict(error='No sender or message overrides accepted'),400
        if not out.OutreachBatch.query.filter_by(id=batch_id,user_id=user.id).first():return dict(error='Batch not found'),404
        return delegate('outreach_cancel_batch',user,method='POST',body={},view_args=dict(batch_id=batch_id))

    @route('/outreach/sequences',['GET'],'agent_sequences',required_scope='outreach:read')
    def read_sequences(user):
        return delegate('sequences',user)

    @route('/outreach/enrollments',['GET'],'agent_enrollments',required_scope='outreach:read')
    def read_enrollments(user):
        return delegate('enrollments',user,args={'page':request.args.get('page',1)})

    @route('/outreach/enrollments/<int:eid>/cancel',['POST'],'agent_cancel_enrollment',required_scope='outreach:send')
    def cancel_enrollment(user,eid):
        if request.get_json(silent=True) not in ({},None):return dict(error='No sender overrides accepted'),400
        return delegate('cancel',user,method='POST',body={},view_args=dict(eid=eid))

    def reply_list(user):
        try: page=max(1,int(request.args.get('page',1)));size=min(100,max(1,int(request.args.get('limit',25))))
        except ValueError:return dict(error='Invalid pagination'),400
        query=svc.SentEmail.query.filter_by(user_id=user.id,responded=True)
        rows=query.order_by(svc.SentEmail.id.desc()).offset((page-1)*size).limit(size).all()
        return dict(items=[dict(id=e.id,school_name=e.school_name,school_email=e.school_email,
            last_reply_date=e.last_reply_date) for e in rows],total=query.count(),page=page),200

    @route('/outreach/replies/<int:email_id>',['GET'],'reply_chain',required_scope='outreach:read')
    def reply_chain(user,email_id):
        if not svc.SentEmail.query.filter_by(id=email_id,user_id=user.id).first():return dict(error='Conversation not found'),404
        return delegate('get_email_reply_chain',user,view_args=dict(email_id=email_id))

    @route('/outreach/drafts',['GET','POST'],'drafts',required_scope='outreach:prepare')
    def drafts(user):
        if request.method=='GET':
            try: page=max(1,int(request.args.get('page',1)))
            except ValueError:return dict(error='Invalid page'),400
            query=Draft.query.filter_by(user_id=user.id,key_id=g.agent_key.id)
            return dict(items=[public(d,False) for d in query.order_by(Draft.created_at.desc(),Draft.id).offset((page-1)*25).limit(25)],total=query.count(),page=page),200
        data=request.get_json(silent=True)
        allowed={'kind','school_ids','audience','campaign_id','contact_contexts','template_id','template_revision','subject','body','attachment_ids'}
        if not isinstance(data,dict) or set(data)-allowed or data.get('kind') not in ('initial','custom','followup'):
            return dict(error='Prepare an initial, custom or followup batch without actor or approval fields'),400
        if not user.email_password:return dict(error='Connect your mailbox first'),400
        settings={**data,'contact_mode':True}
        payload,error=reviewed(user,settings)
        if error:return error
        draft=Draft(id=str(uuid.uuid4()),user_id=user.id,key_id=g.agent_key.id,settings=json.dumps(settings),
            preview=json.dumps(stripped(payload)),review_token=payload['preview_token'],expires_at=svc.utc_now()+timedelta(minutes=15))
        db.session.add(draft);db.session.flush();record(draft,'prepared');db.session.commit()
        return public(draft),201

    @route('/outreach/drafts/<string:did>',['GET'],'draft',required_scope='outreach:prepare')
    def draft_get(user,did):
        draft=Draft.query.filter_by(id=did,user_id=user.id,key_id=g.agent_key.id).first()
        return (public(draft),200) if draft else (dict(error='Draft not found'),404)

    @route('/outreach/drafts/<string:did>/execute',['POST'],'execute',required_scope='outreach:send')
    def execute(user,did):
        if request.get_json(silent=True) not in ({},None):return dict(error='Execute accepts no message, sender or approval arguments'),400
        db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        draft=own(did,user,True)
        if not draft or draft.key_id!=g.agent_key.id:return dict(error='Draft not found'),404
        key=Key.query.filter_by(id=draft.key_id).populate_existing().with_for_update().first()
        if not key_valid(key,user.id,'outreach:send'):return dict(error='Delegation expired or revoked'),403
        if draft.batch_id:return dict(batch_id=draft.batch_id,repeated=True),200
        if draft.status!='approved' or not draft.approval_id or draft.approved_by!=user.id or draft.expires_at<=svc.utc_now():
            return dict(error='A current human approval is required'),409
        data={**json.loads(draft.settings),'preview_token':draft.review_token}
        options,error=out.parse_request_options(data,out.MAX_BATCH_SCHOOLS)
        if error:
            response,status=error;return response.get_json(),status
        payload,status,batch=svc.queue_contact_outreach(user,options,data,agent_draft=draft)
        return payload,status

    @app.get('/api/agent-outreach-drafts')
    @jwt_required()
    def human_drafts():
        user=sender()
        if not user:return jsonify(error='User not found'),404
        try:page=max(1,int(request.args.get('page',1)))
        except ValueError:return jsonify(error='Invalid page'),400
        query=Draft.query.filter_by(user_id=user.id)
        return jsonify(items=[public(d,False) for d in query.order_by(Draft.created_at.desc(),Draft.id).offset((page-1)*25).limit(25)],total=query.count(),page=page)

    @app.get('/api/agent-outreach-drafts/<string:did>')
    @jwt_required()
    def human_draft(did):
        user=sender();draft=own(did,user) if user else None
        if not draft:return jsonify(error='Draft not found'),404
        return jsonify(public(draft))

    @app.post('/api/agent-outreach-drafts/<string:did>/<string:action>')
    @jwt_required()
    def human_decision(did,action):
        user=sender();data=request.get_json(silent=True)
        if not user:return jsonify(error='User not found'),404
        db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
        draft=own(did,user,True)
        if not draft:return jsonify(error='Draft not found'),404
        if not isinstance(data,dict) or set(data)!={'revision'} or data['revision']!=draft.revision:return jsonify(error='Draft changed. Review again.'),409
        if action=='revoke':
            draft.status='revoked';draft.revision+=1;record(draft,'revoked');db.session.commit();return jsonify(public(draft))
        if draft.batch_id or draft.status=='revoked':return jsonify(error='Draft already queued or revoked'),409
        if not key_valid(db.session.get(Key,draft.key_id),user.id):return jsonify(error='Preparing key expired or revoked'),409
        if action=='refresh':
            expected=draft.revision
            payload,error=reviewed(user,json.loads(draft.settings))
            if error:return error
            db.session.query(svc.User.id).filter_by(id=user.id).with_for_update().first()
            db.session.expire_all();draft=own(did,user,True)
            if not draft or draft.revision!=expected or draft.batch_id or draft.status=='revoked':return jsonify(error='Draft changed. Review again.'),409
            draft.preview=json.dumps(stripped(payload));draft.review_token=payload['preview_token'];draft.revision+=1
            draft.status='awaiting';draft.approval_id=None;draft.approved_by=None;draft.approved_at=None
            draft.expires_at=svc.utc_now()+timedelta(minutes=15);record(draft,'refreshed')
        elif action=='approve':
            if draft.status!='awaiting' or draft.expires_at<=svc.utc_now():return jsonify(error='Refresh and review the draft again'),409
            if not any(r['eligible'] for r in json.loads(draft.preview)['previews']):return jsonify(error='No eligible recipients'),409
            draft.status='approved';draft.approval_id=str(uuid.uuid4());draft.approved_by=user.id;draft.approved_at=svc.utc_now()
            record(draft,'approved')
        else:return jsonify(error='Unknown action'),404
        db.session.commit();return jsonify(public(draft))

    def batch_guard(batch_id):
        draft=Draft.query.filter_by(batch_id=batch_id).first()
        if not draft:return None
        from .agent_api import enabled
        if not enabled():return 'Agent API disabled'
        if draft.status!='queued' or not draft.approval_id or draft.approved_by!=draft.user_id:return 'Agent batch approval revoked'
        if draft.expires_at<=svc.utc_now():return 'Agent batch approval expired'
        if not key_valid(db.session.get(Key,draft.key_id),draft.user_id,'outreach:send'):return 'Agent send delegation expired or revoked'
        return None
    svc.agent_batch_guard=batch_guard
