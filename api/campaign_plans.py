"""Employee-approved, frozen campaign scope. Only the dedicated worker dispatches.

Agent keys can prepare/read/stop plans, never approve them. Approval uses the
employee's separate JWT session, including the private Kairos session broker.
"""
import json
import os
import uuid
from datetime import date, datetime, time, timedelta, timezone
from types import SimpleNamespace

from flask import jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import select, update, case, event as sa_event, inspect
from .contact_outreach import digest
from .sequences import EASTERN, utc, next_window, nominal_due
from .template_library import render_copy


def register_campaign_plans(app, db, svc, out):
    class Plan(db.Model):
        __tablename__ = 'approved_campaign_plans'
        id = db.Column(db.String(36), primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
        key_id = db.Column(db.Integer, db.ForeignKey('agent_api_keys.id'), nullable=False)
        revision = db.Column(db.Integer, nullable=False, default=1)
        dispatch_round = db.Column(db.Integer, nullable=False, default=0)
        status = db.Column(db.String(20), nullable=False, default='awaiting')
        settings = db.Column(db.Text, nullable=False)
        snapshot = db.Column(db.Text, nullable=False)
        created_at = db.Column(db.DateTime, nullable=False, default=out.now)
        review_until = db.Column(db.DateTime, nullable=False)
        approved_at = db.Column(db.DateTime)
        approval_id = db.Column(db.String(36))
        reason = db.Column(db.Text)

    class Member(db.Model):
        __tablename__ = 'approved_campaign_members'
        id = db.Column(db.Integer, primary_key=True)
        plan_id = db.Column(db.String(36), db.ForeignKey('approved_campaign_plans.id'), nullable=False, index=True)
        contact_id = db.Column(db.Integer, db.ForeignKey('contacts.id'), nullable=False)
        school_id = db.Column(db.Integer, db.ForeignKey('sales_schools.id',ondelete='SET NULL'), index=True)
        snapshot = db.Column(db.Text, nullable=False)
        status = db.Column(db.String(20), nullable=False, default='waiting')
        reason = db.Column(db.Text)
        recipient_id = db.Column(db.Integer, db.ForeignKey('outreach_recipients.id'), unique=True)
        enrollment_id = db.Column(db.Integer, db.ForeignKey('mail_sequence_enrollments.id'), unique=True)
        __table_args__ = (db.UniqueConstraint('plan_id', 'contact_id'),)

    class Event(db.Model):
        __tablename__ = 'approved_campaign_events'
        id = db.Column(db.Integer, primary_key=True)
        plan_id = db.Column(db.String(36), db.ForeignKey('approved_campaign_plans.id'), nullable=False, index=True)
        event = db.Column(db.String(40), nullable=False)
        revision = db.Column(db.Integer, nullable=False)
        created_at = db.Column(db.DateTime, nullable=False, default=out.now)

    class Summary(db.Model):
        __tablename__ = 'approved_campaign_summaries'
        id = db.Column(db.Integer, primary_key=True)
        plan_id = db.Column(db.String(36), db.ForeignKey('approved_campaign_plans.id'), nullable=False)
        day = db.Column(db.String(10), nullable=False)
        payload = db.Column(db.Text, nullable=False)
        __table_args__ = (db.UniqueConstraint('plan_id', 'day'),)

    svc.CampaignPlan, svc.CampaignMember, svc.CampaignPlanEvent, svc.CampaignSummary = Plan, Member, Event, Summary

    @sa_event.listens_for(svc.SalesSchool,'after_update')
    def persist_school_stop(_mapper,connection,school):
        if inspect(school).attrs.status.history.has_changes() and school.status in ('replied','meeting','partner','former','not_interested'):
            connection.execute(update(Member).where(Member.school_id==school.id,Member.status.in_(('waiting','queued'))).values(status='skipped',reason='School stage stopped outreach'))
            connection.execute(update(out.OutreachRecipient).where(out.OutreachRecipient.id.in_(select(Member.recipient_id).where(Member.school_id==school.id,Member.status=='skipped')),out.OutreachRecipient.status=='queued').values(status='cancelled',error='School stage stopped outreach'))

    def retire_pending(plan):
        members=Member.query.filter_by(plan_id=plan.id).all()
        ids=[m.recipient_id for m in members if m.recipient_id]
        enrollments=[m.enrollment_id for m in members if m.enrollment_id]
        ids += [step.recipient_id for step in svc.SequenceStep.query.filter(svc.SequenceStep.enrollment_id.in_(enrollments)) if step.recipient_id]
        db.session.execute(update(out.OutreachRecipient).where(out.OutreachRecipient.id.in_(ids),out.OutreachRecipient.status=='queued').values(status='cancelled',error='Campaign authorization ended'))
        db.session.execute(update(svc.SequenceEnrollment).where(svc.SequenceEnrollment.id.in_(enrollments),svc.SequenceEnrollment.status=='active').values(status='paused',reason='Campaign authorization ended'))
        db.session.execute(update(svc.SequenceStep).where(svc.SequenceStep.enrollment_id.in_(enrollments),svc.SequenceStep.status.in_(('waiting','checking','queued'))).values(status='stopped',approved_until=None))
        for member in members:
            if member.status=='waiting':member.status='skipped';member.reason='Campaign authorization ended'

    def event(plan, name):
        db.session.add(Event(plan_id=plan.id, revision=plan.revision, event=name))

    def locked(pid, uid):
        db.session.query(svc.User.id).filter_by(id=uid).with_for_update().first()
        return Plan.query.filter_by(id=pid, user_id=uid).populate_existing().with_for_update().first()

    def prepare(user, data, anchor):
        allowed = {'name', 'school_ids', 'audience', 'campaign_id', 'contact_contexts', 'template_id', 'template_revision',
                   'sequence_id', 'sequence_revision', 'daily_cap', 'start_date', 'end_date'}
        if not isinstance(data, dict) or set(data)-allowed: raise ValueError('Supply campaign settings without sender or approval fields')
        if not isinstance(data.get('name'), str) or not 1 <= len(data['name'].strip()) <= 150: raise ValueError('Enter a campaign name')
        if type(data.get('daily_cap')) is not int or not 1 <= data['daily_cap'] <= out.daily_limit(): raise ValueError('Choose a cap within the platform limit')
        cfg = None
        if data.get('sequence_id') is not None:
            sequence = db.session.get(svc.MailSequence, data['sequence_id']) if type(data['sequence_id']) is int else None
            if not sequence or sequence.archived or sequence.revision != data.get('sequence_revision'): raise ValueError('Choose the current sequence version')
            cfg = json.loads(sequence.definition)
            if cfg['audience'] != data.get('audience', 'all'): raise ValueError('Match the sequence audience')
        start, end = (cfg['start_hour'], cfg['end_hour']) if cfg else (9, 17)
        today = anchor.replace(tzinfo=timezone.utc).astimezone(EASTERN).date()
        try: first, last = date.fromisoformat(data['start_date']), date.fromisoformat(data['end_date'])
        except (KeyError, ValueError, TypeError): raise ValueError('Choose start and end dates')
        if not today <= first <= last <= today+timedelta(days=90): raise ValueError('Use a date range within 90 days')
        starts, ends = utc(datetime.combine(first, time(start), EASTERN)), utc(datetime.combine(last, time(end), EASTERN))
        if ends <= anchor: raise ValueError('Choose a future end date')
        intro_data = {k: data[k] for k in ('school_ids','audience','campaign_id','contact_contexts','template_id','template_revision') if k in data}
        intro_data.update(kind='initial', contact_mode=True)
        options, error = out.parse_request_options(intro_data, 500, preview_limit=500)
        if error: raise ValueError(error[0].get_json()['error'])
        if not options.get('template'): raise ValueError('Choose a saved introduction template')
        rows, campaign = svc.resolve_campaign_contacts(user, options, intro_data, max_contacts=1000)
        if data['daily_cap'] > campaign['daily_limit']: raise ValueError('Cap exceeds the shared campaign limit')
        if not rows or not any(r['eligible'] for r in rows): raise ValueError('No eligible contacts')
        for row in rows:
            row['approved_fingerprint']=svc.outreach_fingerprint(dict(to_email=row['email'],subject=row['subject'],body=row['body'],pdf_files=row['pdf_files']))
            row['followups'] = []
            for item in cfg['steps'] if cfg else []:
                template = item['template']
                current = db.session.get(svc.MailTemplate, template['id'])
                if not current or current.archived or current.revision != template['revision']: raise ValueError('Update the sequence after a template change')
                shadow = SimpleNamespace(school_name=row['school_name'], contact_name=row['contact_name'])
                subject, body = render_copy(template['subject'], template['body'], shadow, user)
                files = ['template-asset:'+a['id'] for a in template.get('attachments', [])]
                row['followups'].append(dict(number=item['number'], day=item['day'], subject=subject, body=body, pdf_files=files,
                    attachments=[a['name'] for a in template.get('attachments', [])],
                    fingerprint=svc.outreach_fingerprint(dict(to_email=row['email'],subject=subject,body=body,pdf_files=files))))
        return dict(name=data['name'].strip(),sender_email=user.email,sender_name=user.name, rows=rows, campaign=campaign, intro=options['template'], sequence=cfg,
                    starts_at=out.iso(starts), ends_at=out.iso(ends), start_hour=start, end_hour=end, daily_cap=data['daily_cap'])

    def public(plan, detail=True):
        key=db.session.get(svc.AgentApiKey,plan.key_id)
        result = dict(automation_enabled=enabled(),id=plan.id, name=json.loads(plan.snapshot)['name'], revision=plan.revision, status=plan.status, reason=plan.reason, approval_id=plan.approval_id,
                      approved_at=out.iso(plan.approved_at), review_until=out.iso(plan.review_until),delegation_expires_at=out.iso(key.expires_at) if key else None)
        if detail:
            result.update(settings=json.loads(plan.settings), preview=json.loads(plan.snapshot),
                events=[dict(event=e.event,revision=e.revision,at=out.iso(e.created_at)) for e in Event.query.filter_by(plan_id=plan.id).order_by(Event.id.desc()).limit(50)])
        return result

    def key_ok(plan):
        from .agent_api import enabled
        key = db.session.get(svc.AgentApiKey, plan.key_id)
        return enabled() and key and key.user_id == plan.user_id and not key.revoked_at and key.expires_at > out.now() and 'outreach:send' in key.scopes.split(',')

    def validity(plan):
        if not plan.approval_id: return 'Campaign not approved'
        if not key_ok(plan): return 'Delegated sending expired or revoked'
        snap = json.loads(plan.snapshot)
        sender=db.session.get(svc.User,plan.user_id)
        if not sender or sender.email!=snap['sender_email'] or sender.name!=snap['sender_name']:return 'Sender changed; review campaign again'
        contact_ids=select(Member.contact_id).where(Member.plan_id==plan.id)
        if svc.MailContactSignal.query.filter(svc.MailContactSignal.contact_id.in_(contact_ids),svc.MailContactSignal.created_at>=plan.approved_at).first():return 'Recipient feedback needs review'
        recipient_ids=select(Member.recipient_id).where(Member.plan_id==plan.id)
        if out.OutreachRecipient.query.filter(out.OutreachRecipient.id.in_(recipient_ids),out.OutreachRecipient.status.in_(('failed','unconfirmed'))).first():return 'Delivery needs review'
        snap = json.loads(plan.snapshot)
        if out.now() >= datetime.fromisoformat(snap['ends_at'].rstrip('Z')): return 'Campaign expired'
        templates = [snap['intro']] + [s['template'] for s in snap['sequence']['steps']] if snap['sequence'] else [snap['intro']]
        for template in templates:
            current = db.session.get(svc.MailTemplate, template['id'])
            if not current or current.archived or current.revision != template['revision']: return 'Template changed; review campaign again'
        if snap['sequence']:
            cfg = db.session.get(svc.MailSequence,json.loads(plan.settings)['sequence_id'])
            if not cfg or cfg.archived or cfg.revision != json.loads(plan.settings)['sequence_revision']: return 'Sequence changed; review campaign again'
        campaign = snap['campaign']
        if campaign['id'] != 'standard':
            current = db.session.get(svc.OutreachCampaign,campaign['id'])
            if not current or current.archived or current.daily_limit != campaign['daily_limit']: return 'Shared campaign changed; review again'
        return None

    def own_batch_plan(bid):
        batch = db.session.get(out.OutreachBatch,bid)
        if not batch: return None
        member = Member.query.join(out.OutreachRecipient,Member.recipient_id==out.OutreachRecipient.id).filter(out.OutreachRecipient.batch_id==bid).first()
        if not member:
            member = Member.query.join(svc.SequenceStep,Member.enrollment_id==svc.SequenceStep.enrollment_id).join(
                out.OutreachRecipient,svc.SequenceStep.recipient_id==out.OutreachRecipient.id).filter(out.OutreachRecipient.batch_id==bid).first()
        return db.session.get(Plan,member.plan_id) if member else None

    def recipient_guard(recipient):
        member=Member.query.filter_by(recipient_id=recipient.id).first()
        if not member:return None
        if member.status!='queued':return member.reason or 'Campaign contact stopped'
        row=json.loads(member.snapshot)
        try:actual=svc.outreach_fingerprint(dict(to_email=recipient.email,subject=recipient.subject,body=recipient.body,pdf_files=json.loads(recipient.attachments or '[]')))
        except (ValueError,OSError):return 'Approved campaign attachment unavailable'
        return None if actual==row['approved_fingerprint'] else 'Campaign message or PDF changed; review again'

    def enrollment_block(eid):
        member = Member.query.filter_by(enrollment_id=eid).first()
        plan = db.session.get(Plan,member.plan_id) if member else None
        if not plan: return None
        return plan.reason or 'Campaign '+plan.status if plan.status not in ('approved','running','scheduled') else validity(plan)

    def enabled(): return os.getenv('CAMPAIGN_AUTOMATION_ENABLED','false').lower() == 'true'

    def dispatch_gate(bid):
        plan = own_batch_plan(bid)
        if not plan: return None
        reason = None if plan.status in ('approved','scheduled','running') else 'Campaign '+plan.status
        reason = reason or validity(plan)
        if not enabled(): reason = 'Campaign automation disabled'
        snap = json.loads(plan.snapshot)
        moment = out.now()
        allowed = next_window(max(moment,datetime.fromisoformat(snap['starts_at'].rstrip('Z'))),snap['start_hour'],snap['end_hour'])
        if not reason and out.campaign_used(plan.user_id,snap['campaign']['id'],include_reservations=False)>=snap['daily_cap']:
            allowed=next_window(out.day_bounds()[1],snap['start_hour'],snap['end_hour'])
        if not reason and allowed > moment:
            db.session.execute(update(out.OutreachBatch).where(out.OutreachBatch.id==bid).values(status='queued',available_at=allowed,lease_owner=None,lease_until=None))
            db.session.commit(); return 'Outside campaign window'
        if reason:
            db.session.execute(update(out.OutreachBatch).where(out.OutreachBatch.id==bid,out.OutreachBatch.status.in_(('queued','sending'))).values(
                status='paused',paused_reason=reason,lease_owner=None,lease_until=None))
            db.session.commit()
        return reason

    def list_plans(user):
        try: page=max(1,int(request.args.get('page',1)))
        except ValueError: return dict(error='Invalid page'),400
        query=Plan.query.filter_by(user_id=user.id)
        return dict(items=[public(p,False) for p in query.order_by(Plan.created_at.desc(),Plan.id).offset((page-1)*25).limit(25)],total=query.count(),page=page),200

    def make(user, key_id):
        data=request.get_json(silent=True)
        try: snapshot=prepare(user,data,out.now())
        except (ValueError,PermissionError) as exc: return dict(error=str(exc)),400
        plan=Plan(id=str(uuid.uuid4()),user_id=user.id,key_id=key_id,settings=json.dumps(data),snapshot=json.dumps(snapshot),review_until=out.now()+timedelta(minutes=15))
        db.session.add(plan);db.session.flush();event(plan,'prepared');db.session.commit()
        return public(plan),201

    def decision(user,pid,action):
        plan=locked(pid,user.id)
        if not plan: return dict(error='Campaign not found'),404
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)-{'revision','confirm','settings'} or type(data.get('revision')) is not int or data['revision']!=plan.revision: return dict(error='Campaign changed; review again'),409
        allowed={'revision','confirm'} if action=='approve' else {'revision','settings'} if action=='refresh' else {'revision'}
        if set(data)-allowed:return dict(error='This action accepts no scope or message overrides'),400
        if plan.status in ('cancelled','completed','expired'): return dict(error='Campaign is terminal; prepare a new campaign'),409
        if action=='approve':
            if data.get('confirm')!='AUTHORIZE_CAMPAIGN' or plan.status!='awaiting' or plan.review_until<=out.now(): return dict(error='Review current campaign and explicitly authorize it'),409
            frozen=json.loads(plan.snapshot)
            db.session.query(svc.SalesSchool.id).filter(svc.SalesSchool.id.in_([r['school_id'] for r in frozen['rows']])).order_by(svc.SalesSchool.id).with_for_update().all()
            db.session.query(svc.Contact.id).filter(svc.Contact.id.in_([r['contact_id'] for r in frozen['rows']])).order_by(svc.Contact.id).with_for_update().all()
            try: fresh=prepare(user,json.loads(plan.settings),plan.created_at)
            except (ValueError,PermissionError) as exc:return dict(error=str(exc)),409
            if digest(fresh)!=digest(json.loads(plan.snapshot)):return dict(error='Contact, template or scope changed; refresh review'),409
            if not key_ok(plan):return dict(error='Delegate approved sending to the preparing key first'),409
            plan.approval_id=str(uuid.uuid4());plan.approved_at=out.now();plan.status='scheduled';plan.reason=None
            for row in fresh['rows']:
                db.session.add(Member(plan_id=plan.id,contact_id=row['contact_id'],school_id=row['school_id'],snapshot=json.dumps(row),status='waiting' if row['eligible'] else 'skipped',reason=None if row['eligible'] else ', '.join(row['blockers'])))
        elif action=='pause':
            if plan.status not in ('scheduled','approved','running'):return dict(error='Only active campaigns can pause'),409
            plan.status='paused';plan.reason='Paused by employee'
        elif action=='resume':
            if plan.status!='paused' or validity(plan):return dict(error=validity(plan) or 'Campaign is not paused'),409
            # Only explicit employee pauses resume. Feedback and uncertain outcomes require a new review.
            if plan.reason!='Paused by employee':return dict(error='Resolve the error and prepare a new campaign'),409
            plan.status='scheduled';plan.reason=None
            for batch in out.OutreachBatch.query.filter_by(user_id=user.id,status='paused').all():
                linked=own_batch_plan(batch.id)
                if linked and linked.id==plan.id and batch.paused_reason=='Campaign paused':batch.status='queued';batch.paused_reason=None
        elif action=='cancel':
            plan.status='cancelled';plan.reason='Cancelled by employee';retire_pending(plan)
        elif action=='refresh':
            if plan.approval_id:return dict(error='Cancel the approved campaign and prepare a new scope'),409
            settings=data.get('settings',json.loads(plan.settings))
            try:snapshot=prepare(user,settings,out.now())
            except (ValueError,PermissionError) as exc:return dict(error=str(exc)),400
            plan.settings=json.dumps(settings);plan.snapshot=json.dumps(snapshot);plan.created_at=out.now();plan.review_until=out.now()+timedelta(minutes=15);plan.revision+=1
        else:return dict(error='Unknown action'),404
        if action!='refresh':plan.revision+=1
        event(plan,action);db.session.commit();return public(plan),200

    @app.get('/api/outreach/campaign-plans')
    @jwt_required()
    def campaign_plans():
        user=out.current_user()
        return _list_response(user)

    def _list_response(user):
        if not user:return jsonify(error='User not found'),404
        payload,status=list_plans(user);return jsonify(payload),status

    @app.get('/api/outreach/campaign-plans/<string:pid>')
    @jwt_required()
    def campaign_plan(pid):
        user=out.current_user();plan=Plan.query.filter_by(id=pid,user_id=user.id).first() if user else None
        return (jsonify(public(plan)),200) if plan else (jsonify(error='Campaign not found'),404)

    @app.post('/api/outreach/campaign-plans/<string:pid>/<string:action>')
    @jwt_required()
    def campaign_decision(pid,action):
        user=out.current_user()
        if not user:return jsonify(error='User not found'),404
        payload,status=decision(user,pid,action);return jsonify(payload),status

    def summary(plan):
        members=Member.query.filter_by(plan_id=plan.id).all()
        recipient_ids=[m.recipient_id for m in members if m.recipient_id]
        eids=[m.enrollment_id for m in members if m.enrollment_id]
        recipient_ids += [s.recipient_id for s in svc.SequenceStep.query.filter(svc.SequenceStep.enrollment_id.in_(eids)) if s.recipient_id]
        rows=out.OutreachRecipient.query.filter(out.OutreachRecipient.id.in_(recipient_ids)).all()
        start,end=out.day_bounds()
        day=out.now().replace(tzinfo=timezone.utc).astimezone(EASTERN).date().isoformat()
        counts={s:sum(r.status==s and start<=(r.sent_at or r.attempted_at or start)<end for r in rows) for s in ('sent','failed','unconfirmed')}
        originals=[r.sent_email_id for r in rows if r.sent_email_id]
        contacts=[m.contact_id for m in members]
        signals=svc.MailContactSignal.query.filter(svc.MailContactSignal.contact_id.in_(contacts),svc.MailContactSignal.created_at>=start,svc.MailContactSignal.created_at<end).all()
        payload=dict(automation_enabled=enabled(),day=day,status=plan.status,reason=plan.reason,smtp_accepted=counts['sent'],failed=counts['failed'],unconfirmed=counts['unconfirmed'],
            remaining_contacts=sum(m.status in ('waiting','queued') for m in members),skipped_cumulative=sum(m.status=='skipped' for m in members),
            replied_cumulative=svc.SentEmail.query.filter(svc.SentEmail.id.in_(originals),svc.SentEmail.responded.is_(True)).count(),
            bounces=sum(s.kind=='hard_bounce' for s in signals),optouts=sum(s.kind in ('optout','complaint') for s in signals),
            mailbox_quota=out.limits_for(db.session.get(svc.User,plan.user_id)),delivery_note='SMTP acceptance is not confirmed inbox delivery. Reply and skip counts are cumulative; sending and signals use the Eastern day. Signals concern approved contacts, not proof this campaign caused them.')
        saved=Summary.query.filter_by(plan_id=plan.id,day=day).first()
        if not saved:saved=Summary(plan_id=plan.id,day=day,payload='{}');db.session.add(saved)
        saved.payload=json.dumps(payload);return payload

    @app.get('/api/outreach/campaign-plans/<string:pid>/summary')
    @jwt_required()
    def campaign_summary(pid):
        user=out.current_user();plan=locked(pid,user.id) if user else None
        if not plan:return jsonify(error='Campaign not found'),404
        payload=summary(plan);db.session.commit();return jsonify(payload)

    svc.campaign_plan_list,svc.campaign_plan_make,svc.campaign_plan_public=list_plans,make,public
    svc.campaign_plan_decision,svc.campaign_plan_summary=decision,summary
    svc.campaign_dispatch_gate,svc.campaign_enrollment_block=dispatch_gate,enrollment_block
    svc.campaign_plan_prepare,svc.campaign_plan_validity=prepare,validity

    def reconcile(plan):
        snap=json.loads(plan.snapshot)
        for member in Member.query.filter_by(plan_id=plan.id,status='queued').all():
            recipient=db.session.get(out.OutreachRecipient,member.recipient_id)
            batch=db.session.get(out.OutreachBatch,recipient.batch_id)
            if batch.status=='paused' and batch.paused_reason and batch.paused_reason!='Campaign paused':
                plan.status='paused';plan.reason=batch.paused_reason;event(plan,'delivery_paused')
            if recipient.status=='sent':
                if member.enrollment_id:continue
                row=json.loads(member.snapshot)
                if not row['followups']:member.status='done';continue
                original=db.session.get(svc.SentEmail,recipient.sent_email_id)
                cfg=snap['sequence'];settings=json.loads(plan.settings)
                enrollment=svc.SequenceEnrollment(original_id=original.id,user_id=plan.user_id,school_id=row['school_id'],contact_id=row['contact_id'],sequence_id=settings['sequence_id'],revision=settings['sequence_revision'],campaign_id=snap['campaign']['id'],mode='automatic',
                    snapshot=json.dumps(dict(school_name=row['school_name'],email=row['email'],link_id=row['contact_link_id'],link_version=row['signature']['link_version'],contact_version=row['signature']['contact_version'],ownership_version=row['signature']['owner_version'],definition=cfg)),
                    starts_at=datetime.fromisoformat(snap['starts_at'].rstrip('Z')),ends_at=datetime.fromisoformat(snap['ends_at'].rstrip('Z')))
                db.session.add(enrollment);db.session.flush();member.enrollment_id=enrollment.id;original.sequence_managed=True
                for item in row['followups']:
                    due=nominal_due(original.sent_at,item['day'],cfg['start_hour'],cfg['end_hour'])
                    db.session.add(svc.SequenceStep(enrollment_id=enrollment.id,number=item['number'],due_at=due,content=json.dumps(item)))
            elif recipient.status in ('failed','unconfirmed'):
                member.status=recipient.status;member.reason=recipient.error;plan.status='paused';plan.reason='Delivery needs review';event(plan,'delivery_paused')
            elif recipient.status in ('skipped','cancelled'):member.status='skipped';member.reason=recipient.error
        for member in Member.query.filter_by(plan_id=plan.id).filter(Member.enrollment_id.isnot(None)).all():
            enrollment=db.session.get(svc.SequenceEnrollment,member.enrollment_id)
            if enrollment.status=='done':member.status='done'
            elif enrollment.status!='active':member.status='skipped';member.reason=enrollment.reason

    def schedule(limit=5):
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('Use a scheduling limit between 1 and 20')
        if not enabled():return 0
        total=0
        for pid,uid in db.session.query(Plan.id,Plan.user_id).filter(Plan.status.in_(('scheduled','running','paused'))).order_by(case((Plan.status=='paused',1),else_=0),Plan.dispatch_round,Plan.created_at,Plan.id).limit(50).all():
            plan=locked(pid,uid)
            if plan.status not in ('scheduled','running','paused'):db.session.rollback();continue
            reason=validity(plan)
            if reason:
                previous=(plan.status,plan.reason);plan.status='expired' if reason=='Campaign expired' else 'paused';plan.reason=reason
                if plan.status=='expired':retire_pending(plan)
                if previous!=(plan.status,plan.reason):event(plan,'authorization_blocked')
                summary(plan);db.session.commit();continue
            reconcile(plan)
            if plan.status=='paused':summary(plan);db.session.commit();continue
            snap=json.loads(plan.snapshot);now=out.now()
            if now < datetime.fromisoformat(snap['starts_at'].rstrip('Z')) or next_window(now,snap['start_hour'],snap['end_hour'])!=now:db.session.commit();continue
            user=db.session.get(svc.User,uid)
            remaining=min(limit-total,out.limits_for(user)['remaining'],snap['daily_cap']-out.campaign_used(uid,snap['campaign']['id']),snap['campaign']['daily_limit']-out.campaign_used(uid,snap['campaign']['id']))
            batch=None
            for member in Member.query.filter_by(plan_id=plan.id,status='waiting').order_by(Member.id).all():
                if remaining<=0:break
                row=json.loads(member.snapshot)
                db.session.query(svc.SalesSchool.id).filter_by(id=row['school_id']).with_for_update().first()
                db.session.query(svc.Contact.id).filter_by(id=row['contact_id']).with_for_update().first()
                school=db.session.get(svc.SalesSchool,row['school_id']);contact=db.session.get(svc.Contact,row['contact_id']);link=db.session.get(svc.SchoolContact,row['contact_link_id'])
                changed=not school or school.user_id!=uid or school.ownership_version!=row['signature']['owner_version'] or not contact or contact.do_not_contact or contact.version!=row['signature']['contact_version'] or not link or link.version!=row['signature']['link_version']
                if changed or school.status in (out.CLOSED_STAGES | out.REPLIED_STAGES):
                    member.status='skipped';member.reason='Contact or school eligibility changed';continue
                ledger=svc.ContactOutreachLedger.query.filter_by(campaign_id=snap['campaign']['id'],contact_id=contact.id,step='intro').first()
                if ledger:
                    previous=db.session.get(out.OutreachRecipient,ledger.recipient_id)
                    if previous.status not in ('cancelled','failed','skipped') or out.OutreachAttempt.query.filter_by(recipient_id=previous.id,status='unconfirmed').first():member.status='skipped';member.reason='Already reserved or contacted';continue
                if svc.SentEmail.query.filter(svc.SentEmail.school_email==row['email'], (svc.SentEmail.sent_at>=out.now()-timedelta(days=out.RECENT_CONTACT_DAYS)) | (svc.SentEmail.responded.is_(True))).first():member.status='skipped';member.reason='Recent outreach or reply since approval';continue
                if out.OutreachRecipient.query.filter_by(email=row['email']).filter(out.OutreachRecipient.status.in_(('queued','sending'))).first():continue
                if row['followups'] and nominal_due(out.now(),max(item['day'] for item in row['followups']),snap['start_hour'],snap['end_hour'])>=datetime.fromisoformat(snap['ends_at'].rstrip('Z')):
                    member.status='skipped';member.reason='Not enough approved time for the follow-up sequence';continue
                if not batch:
                    batch=out.OutreachBatch(user_id=uid,kind='initial',campaign_id=snap['campaign']['id'],status='queued',worker_token=str(uuid.uuid4()),template_snapshot=json.dumps(snap['intro']));db.session.add(batch);db.session.flush()
                recipient=out.OutreachRecipient(batch_id=batch.id,position=total,school_id=school.id,school_name=row['school_name'],email=row['email'],subject=row['subject'],body=row['body'],attachments=json.dumps(row['pdf_files']),status='queued',ownership_version=row['signature']['owner_version'],contact_id=contact.id,contact_link_id=link.id,contact_version=contact.version,link_version=link.version)
                db.session.add(recipient);db.session.flush();member.recipient_id=recipient.id;member.status='queued'
                if ledger:ledger.recipient_id=recipient.id
                else:db.session.add(svc.ContactOutreachLedger(campaign_id=snap['campaign']['id'],contact_id=contact.id,step='intro',recipient_id=recipient.id))
                total+=1;remaining-=1;plan.status='running'
            if batch:plan.dispatch_round+=1
            db.session.flush()
            if not Member.query.filter_by(plan_id=plan.id).filter(Member.status.in_(('waiting','queued'))).first():plan.status='completed';event(plan,'completed')
            summary(plan);db.session.commit()
            if total>=limit:break
        return total

    svc.schedule_campaigns=schedule
    svc.campaign_recipient_guard=recipient_guard
