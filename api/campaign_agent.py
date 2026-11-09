"""Narrow campaign adapters. No agent approval endpoint."""
from flask import request, g


def register_campaign_agent(app, db, svc, route, delegate):
    @route('/outreach/campaign-plans',['GET','POST'],'campaign_plans',required_scope='outreach:prepare')
    def plans(user):
        return svc.campaign_plan_make(user,g.agent_key.id) if request.method=='POST' else svc.campaign_plan_list(user)

    @route('/outreach/campaign-plans/<string:pid>',['GET'],'campaign_plan',required_scope='outreach:read')
    def plan(user,pid):
        row=svc.CampaignPlan.query.filter_by(id=pid,user_id=user.id).first()
        return (svc.campaign_plan_public(row),200) if row else (dict(error='Campaign not found'),404)

    @route('/outreach/campaign-plans/<string:pid>/summary',['GET'],'campaign_summary',required_scope='outreach:read')
    def summary(user,pid):
        return delegate('campaign_summary',user,view_args=dict(pid=pid))

    @route('/outreach/campaign-plans/<string:pid>/stop',['POST'],'campaign_stop',required_scope='outreach:send')
    def stop(user,pid):
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)!={'revision','action'} or data['action'] not in ('pause','cancel'):
            return dict(error='Only revision-bound pause or cancel accepted'),400
        return delegate('campaign_decision',user,method='POST',body=dict(revision=data['revision']),view_args=dict(pid=pid,action=data['action']))
