"""Cohort reply rates and daily sending receipts; never sends summary emails."""
import json
from collections import defaultdict
from datetime import date,datetime,time,timedelta,timezone
from zoneinfo import ZoneInfo
from flask import jsonify,request
from flask_jwt_extended import jwt_required,get_jwt_identity


def register_sales_reporting(app,db,svc):
    @app.get('/api/outreach/reporting')
    @jwt_required()
    def outreach_reporting():
        user=db.session.get(svc.User,int(get_jwt_identity()))
        if not user:return jsonify(error='User not found'),404
        today=datetime.now(ZoneInfo('America/New_York')).date()
        try:
            start=date.fromisoformat(request.args.get('start',str(today-timedelta(days=29))))
            end=date.fromisoformat(request.args.get('end',str(today)))
            if end<start or (end-start).days>365:raise ValueError()
        except ValueError:return jsonify(error='Choose a date range of up to 366 days'),400
        def bound(d):return datetime.combine(d,time.min,ZoneInfo('America/New_York')).astimezone(timezone.utc).replace(tzinfo=None)
        B,R,SE=svc.OutreachBatch,svc.OutreachRecipient,svc.SentEmail
        q=db.session.query(R,B,SE.responded).join(B,B.id==R.batch_id).outerjoin(SE,SE.id==R.sent_email_id).filter(B.kind!='test',db.func.coalesce(R.sent_at,B.created_at)>=bound(start),db.func.coalesce(R.sent_at,B.created_at)<bound(end+timedelta(days=1)))
        if not user.admin:q=q.filter(B.user_id==user.id)
        rows=q.order_by(R.id).limit(10001).all()
        if len(rows)>10000:return jsonify(error='More than 10,000 messages match. Narrow the date range.'),400
        groups={};audiences={};days=defaultdict(lambda:defaultdict(int))
        def cohort(bucket,key,label):return bucket.setdefault(key,dict(key=key,label=label,sent=0,threads=set(),replied=set()))
        totals=defaultdict(int)
        for recipient,batch,responded in rows:
            snap=json.loads(batch.template_snapshot) if batch.template_snapshot else {}
            key=str(snap.get('id') or 'custom');audience=batch.audience or snap.get('audience') or 'not_recorded'
            g=cohort(groups,key,snap.get('name') or 'Custom / historical');a=cohort(audiences,audience,audience.replace('_',' '))
            state=recipient.status
            totals[state]+=1
            day=(recipient.sent_at or batch.created_at).replace(tzinfo=timezone.utc).astimezone(ZoneInfo('America/New_York')).date().isoformat()
            days[day][state]+=1
            if state=='sent':
                for bucket in (g,a):
                    bucket['sent']+=1
                    if recipient.sent_email_id:
                        bucket['threads'].add(recipient.sent_email_id)
                        if responded:bucket['replied'].add(recipient.sent_email_id)
        def finish(bucket):
            return [dict(key=g['key'],label=g['label'],sent=g['sent'],conversations=len(g['threads']),replied=len(g['replied']),reply_rate=round(100*len(g['replied'])/len(g['threads']),1) if g['threads'] else None) for g in bucket.values()]
        return jsonify(start=str(start),end=str(end),timezone='America/New_York',totals=dict(totals),by_template=finish(groups),by_audience=finish(audiences),days=[dict(day=d,**counts) for d,counts in sorted(days.items(),reverse=True)],note='Sent means provider acceptance, not inbox delivery. Reply rates count distinct linked conversations sent in this period and their replies known now. Historical audiences were not always recorded. Self-test mail is excluded.')
