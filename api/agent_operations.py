"""Fixed, permission-scoped business operations shared by chat integrations.

No operation accepts a URL, endpoint name, actor, JWT or approval token. Web
handlers retain their normal ownership, validation and revision checks. Human
send approval, account credentials and delegation management are not exposed.
"""
import base64
import binascii
import io
import re

from flask import g, request

S = {'type': 'string', 'maxLength': 20000}
ID = {'type': 'integer', 'minimum': 1}
BOOL = {'type': 'boolean'}
OPAQUE = {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{1,100}$'}
NULL_ID = {'anyOf': [ID, {'type': 'null'}]}
STRINGS = {'type': 'array', 'items': S, 'maxItems': 50}
IDS = {'type': 'array', 'items': ID, 'minItems': 1, 'maxItems': 100}
FILTERS = {'type': 'object', 'properties': {k: S for k in ('q','stage','type','owner','county','scope','due')}, 'additionalProperties': False}
CONTACT = {'email': S, 'name': S, 'roles': STRINGS, 'tags': STRINGS, 'is_primary': BOOL, 'do_not_contact': BOOL, 'suppression_reason': S}
TEMPLATE = {'name': S, 'kind': {'enum': ['initial','followup']}, 'audience': S, 'step': {'type':'integer','minimum':0,'maximum':3}, 'subject': S, 'body': S, 'attachment_ids': {'type':'array','items':S,'maxItems':3}}
COMMISSION = {k:S for k in ('season','program','sale_type','gross','cash_expenses','notes')}
COMMISSION.update(sales_school_id=ID,rep_id=ID,leagueapps=BOOL,rep_payout={'anyOf':[S,{'type':'null'}]},voided=BOOL,revision=ID)
SEQUENCE = {'name':S,'audience':S,'start_hour':{'type':'integer','minimum':6,'maximum':19},'end_hour':{'type':'integer','minimum':7,'maximum':20},'steps':{'type':'array','minItems':1,'maxItems':3,'items':{'type':'object','properties':{'day':{'type':'integer','minimum':1,'maximum':90},'template_id':ID,'template_revision':ID},'required':['day','template_id','template_revision'],'additionalProperties':False}}}
OPERATIONS = []

def operation(name, description, endpoint, method='GET', properties=None, required=(), scope='read', admin=False, params=None, upload=False):
    OPERATIONS.append(dict(name=name,description=description,endpoint=endpoint,method=method,
        properties=properties or {},required=list(required),scope=scope,admin=admin,params=params or {},upload=upload))

operation('psa_directory','Search the school directory before creating leads. Does not send email.','crm_directory',properties={k:S for k in ('q','type','county','page','limit')})
operation('psa_profile','Read your name, phone and mailbox connection status. Never returns mail credentials.','profile')
operation('psa_edit_profile','Update only the connected employee name or phone. Account credentials remain private.','crm_profile','PATCH',{'name':S,'phone':S},scope='write')
operation('psa_bulk_school_stage','Change the stage of up to 100 accessible schools atomically. Review names and current stages first.','crm_bulk_schools','POST',{'ids':IDS,'status':{'enum':['pending','contacted','replied','meeting','partner','former','not_interested']}},['ids','status'],'write')
operation('psa_create_school','Add a school with duplicate protection. Use contact import for multi-contact lists.','add_school','POST',
    {**{k:S for k in ('school_name','email','contact_name','phone','address','school_type','website','county')},'additional_emails':STRINGS,'shared_contact_confirmed':BOOL},['school_name','email','school_type'],'write')
operation('psa_edit_school','Edit school details, stage, county, notes or next action using normal school access rules.','sales_school_workspace','PATCH',
    {**{k:S for k in ('school_name','email','contact_name','phone','address','school_type','website','county','status','notes','next_action','next_action_at')},'school_id':ID,'user_id':NULL_ID,'additional_emails':STRINGS},['school_id'],'write',params={'school_id':'school_id'})
operation('psa_delete_schools','Permanently delete selected owned schools. Review IDs and names first. Sent history is retained.','crm_delete_schools','POST',{'ids':IDS},['ids'],'write')
operation('psa_add_contact','Add a role-based school contact. Shared mailbox suppression remains global.','school_contacts','POST',{'school_id':ID,**CONTACT},['school_id','email'],'write',params={'school_id':'sid'})
operation('psa_edit_contact','Edit a linked contact using current link and contact versions. Only admins may lift suppression.','patch_contact','PATCH',{'school_id':ID,'link_id':ID,'version':ID,'contact_version':ID,**{k:v for k,v in CONTACT.items() if k!='email'}},['school_id','link_id','version','contact_version'],'write',params={'school_id':'sid','link_id':'lid'})
operation('psa_report_contact','Record an opt-out, complaint or review signal and pause affected outreach. Explain the source.','report','POST',{'contact_id':ID,'kind':{'enum':['optout','complaint','review']},'detail':S},['contact_id','kind','detail'],'write',params={'contact_id':'contact_id'})
operation('psa_assignment_preview','Admin: preview moving matching schools to a rep or the unassigned pool. Never changes owners.','assignment_preview','POST',{'user_id':NULL_ID,'ids':{'type':'array','items':ID,'minItems':1,'maxItems':2000},'filters':FILTERS},['user_id'],'write',True)
operation('psa_assignment_commit','Admin: apply a reviewed, unexpired school assignment. Changed selections require a new preview.','assignment_commit','POST',{'review_id':OPAQUE},['review_id'],'write',True,{'review_id':'rid'})
operation('psa_claim_school','Claim one unassigned school for the connected employee. Competing claims return a conflict.','claim_school','POST',{'school_id':ID},['school_id'],'write',params={'school_id':'sid'})
operation('psa_find_schools','Find nearby schools using address or coordinates, keywords and radius. May call the location provider.','find_schools','POST',{'address':S,'lat':{'type':'number','minimum':-90,'maximum':90},'lng':{'type':'number','minimum':-180,'maximum':180},'radius_km':{'type':'number','minimum':1,'maximum':40},'keywords':STRINGS,'types':STRINGS,'page_token':S})
operation('psa_place_details','Read contact details for a discovered place ID.','find_school_details','POST',{'place_id':S},['place_id'])
operation('psa_save_discovered_schools','Save selected discovered schools with duplicate checks. Reps can assign only to themselves.','save_found_schools','POST',{'schools':{'type':'array','minItems':1,'maxItems':50,'items':{'type':'object','properties':{**{k:S for k in ('place_id','school_name','address','email','phone','website','school_type')},'lat':{'type':'number'},'lng':{'type':'number'}},'required':['place_id','school_name'],'additionalProperties':False}},'assign_to':ID},['schools'],'write')
operation('psa_map_accounts','Read owned school coordinates, stages and rep colors for territory planning.','crm_map_accounts',properties={k:S for k in ('owner','stages','q','county','scope')})
operation('psa_locate_schools','Resolve missing coordinates in a bounded pass using the existing location cache.','crm_locate_accounts','POST',{'limit':{'type':'integer','minimum':1,'maximum':50}},scope='write')
operation('psa_map_layers','Read saved PSA, partner and elementary prospect map layers.','map_schools')
operation('psa_refresh_map_layers','Admin: refresh saved prospect map layers from their configured source.','refresh_map_schools','POST',scope='write',admin=True)
operation('psa_plan_visits','Suggest a bounded visit order from a starting address and selected coordinates. Not driving directions.','route_plan','POST',{'start_address':S,'schools':{'type':'array','minItems':1,'maxItems':25,'items':{'type':'object','properties':{'place_id':S,'name':S,'school_name':S,'lat':{'type':'number'},'lng':{'type':'number'}},'required':['place_id','lat','lng'],'additionalProperties':False}}},['start_address','schools'])
operation('psa_template_versions','Read saved text and PDF revision history for a shared template.','template_versions',properties={'template_id':ID},required=['template_id'],scope='outreach:read',params={'template_id':'tid'})
operation('psa_create_template','Admin: create a shared email template with reusable catalog PDF IDs. Does not send mail.','template_create','POST',TEMPLATE,['name','kind','audience','subject','body'],'library:manage',True)
operation('psa_edit_template','Admin: edit or archive a shared template with its current revision; queued copy stays frozen.','template_edit','PUT',{'template_id':ID,'revision':ID,'archived':BOOL,**TEMPLATE},['template_id','revision'],'library:manage',True,{'template_id':'tid'})
operation('psa_seed_templates','Admin: add missing Winter 2027 templates without replacing later edits.','template_seed','POST',scope='library:manage',admin=True)
operation('psa_publish_pdf','Admin: copy an approved built-in PSA PDF into the reusable catalog.','publish_template_asset','POST',{'filename':S},['filename'],'library:manage',True)
operation('psa_upload_pdf','Admin: upload a chosen PDF to the reusable catalog. Supply filename and base64 bytes; maximum 10 MB decoded. Never sends mail.','upload_template_asset','POST',{'filename':{'type':'string','maxLength':150},'encoded':{'type':'string','maxLength':13981016}},['filename','encoded'],'library:manage',True,upload=True)
operation('psa_upload_templates','Admin: upload template JSON for a review preview. Review then commit; existing edits are preserved.','template_import_preview','POST',{'filename':{'type':'string','maxLength':150},'encoded':{'type':'string','maxLength':1398104}},['filename','encoded'],'library:manage',True,upload=True)
operation('psa_commit_template_import','Admin: commit a reviewed template JSON import by its returned review ID. Stale reviews are rejected.','template_import_commit','POST',{'review_id':OPAQUE},['review_id'],'library:manage',True,{'review_id':'rid'})
operation('psa_create_sequence','Admin: create a versioned follow-up definition; does not enroll or send to contacts.','sequences','POST',SEQUENCE,['name','steps'],'library:manage',True)
operation('psa_edit_sequence','Admin: edit or archive a follow-up definition using its revision. Changes stop existing enrollments so they need a new review.','sequence_edit','PUT',{'sequence_id':ID,'revision':ID,'archived':BOOL,**SEQUENCE},['sequence_id','revision'],'library:manage',True,{'sequence_id':'sid'})
operation('psa_sequence_versions','Read follow-up definition revisions.','versions',properties={'sequence_id':ID},required=['sequence_id'],scope='outreach:read',params={'sequence_id':'sid'})
operation('psa_sequence_originals','Read eligible original messages before preparing a follow-up plan. No enrollment or sending.','originals',properties={k:S for k in ('q','page','per_page')},scope='outreach:read')
operation('psa_mail_limits','Read the connected employee daily sending allowance.','outreach_limits',scope='outreach:read')
operation('psa_outreach_campaigns','Read outreach campaign IDs and their current daily caps. Does not authorize sending.','campaigns',scope='outreach:read')
operation('psa_create_outreach_campaign','Admin: create a distinct outreach campaign label and cap with a reason. Does not approve recipients or start sending.','create_campaign','POST',{'name':S,'reason':S,'daily_limit':{'type':'integer','minimum':1,'maximum':1000}},['name','reason','daily_limit'],'library:manage',True)
operation('psa_worker_status','Read sending worker freshness and queue status.','worker_status',scope='outreach:read')
operation('psa_program_commissions','Admin: read seasonal commission records and rep/season totals.','list_program_commissions',properties={'season':S,'rep_id':ID},admin=True)
operation('psa_create_commission','Admin: record one school/program/season commission with explicit rep payout.','save_program_commission','POST',COMMISSION,['sales_school_id','season','program','rep_id','sale_type','gross','leagueapps','cash_expenses'],'commissions:manage',True)
operation('psa_edit_commission','Admin: correct or void a commission using the current revision; history is preserved.','save_program_commission','PUT',{'record_id':ID,**COMMISSION},['record_id','revision','sales_school_id','season','program','rep_id','sale_type','gross','leagueapps','cash_expenses'],'commissions:manage',True,{'record_id':'record_id'})
operation('psa_commission_history','Admin: read correction history for a seasonal commission.','program_commission_history',properties={'record_id':ID},required=['record_id'],admin=True,params={'record_id':'record_id'})
operation('psa_set_team_access','Admin: change a teammate admin role; normal self/last-admin protections remain.','crm_update_team_member','PATCH',{'member_id':ID,'admin':BOOL},['member_id','admin'],'team:manage',True,{'member_id':'member_id'})
operation('psa_join_links','Admin: list employee join-link metadata.','list_join_links',admin=True)
operation('psa_create_join_link','Admin: create an employee join link with explicit expiry and use limit. Treat the returned invite token as private.','create_join_link','POST',{'days':{'enum':[1,7,14,30]},'max_uses':{'type':'integer','minimum':1,'maximum':200},'label':S},['days','max_uses'],'team:manage',True)
operation('psa_revoke_join_link','Admin: revoke one employee join link.','revoke_join_link','DELETE',{'link_id':ID},['link_id'],'team:manage',True,{'link_id':'link_id'})


def valid(schema, value):
    if 'anyOf' in schema:return any(valid(s,value) for s in schema['anyOf'])
    if 'enum' in schema:return value in schema['enum'] and not (isinstance(value,bool) and all(type(v) is int for v in schema['enum']))
    kind=schema.get('type')
    if kind=='null':return value is None
    if kind=='boolean':return type(value) is bool
    if kind in ('integer','number'):
        import math
        return type(value) in ((int,) if kind=='integer' else (int,float)) and math.isfinite(value) and schema.get('minimum',value)<=value<=schema.get('maximum',value)
    if kind=='string':return isinstance(value,str) and len(value)<=schema.get('maxLength',20000) and (not schema.get('pattern') or bool(re.fullmatch(schema['pattern'],value)))
    if kind=='array':return isinstance(value,list) and schema.get('minItems',0)<=len(value)<=schema.get('maxItems',100) and all(valid(schema['items'],v) for v in value)
    if kind=='object':return isinstance(value,dict) and not set(value)-set(schema['properties']) and not set(schema.get('required',[]))-set(value) and all(valid(schema['properties'][k],v) for k,v in value.items())
    return False


def register_agent_operations(app, route, delegate):
    by_name={op['name']:op for op in OPERATIONS}

    @route('/capabilities',['GET'],'business_capabilities')
    def capabilities(user):
        scopes=set(g.agent_key.scopes.split(','))
        return dict(operations=[dict(name=op['name'],scope=op['scope'],admin=op['admin'],
            available=op['endpoint'] in app.view_functions,authorized=op['scope'] in scopes and (not op['admin'] or bool(user.admin))) for op in OPERATIONS],
            human_only=['mail/account credentials','API key delegation','final send/campaign/sequence approval'],
            chat_connection='Select PSA Command in this chat integration menu. Adding a server does not select it in every chat.'),200

    @route('/operations/<string:name>',['POST'],'business_operation',required_scope='read',body_limit=15*1024*1024)
    def run(user,name):
        op=by_name.get(name)
        if not op:return dict(error='Unknown business operation'),404
        if op['scope'] not in g.agent_key.scopes.split(','):return dict(error='This key requires '+op['scope']+' permission'),403
        if op['admin'] and not user.admin:return dict(error='Administrator access required'),403
        if not op['upload'] and (request.content_length or 0)>32768:return dict(error='Request too large'),413
        data=request.get_json(silent=True)
        if not isinstance(data,dict) or set(data)-set(op['properties']) or set(op['required'])-set(data) or any(not valid(op['properties'][k],v) for k,v in data.items()):
            return dict(error='Supply only the documented operation fields'),400
        params={target:data[key] for key,target in op['params'].items()}
        body={k:v for k,v in data.items() if k not in op['params']}
        if op['upload']:
            filename,encoded=body['filename'],body['encoded']
            pdf=name=='psa_upload_pdf';limit=10*1024*1024 if pdf else 1024*1024
            if not re.fullmatch(r'[A-Za-z0-9 _.-]{1,150}',filename) or not filename.lower().endswith('.pdf' if pdf else '.json'):
                return dict(error='Choose a valid upload filename'),400
            try:raw=base64.b64decode(encoded,validate=True)
            except (ValueError,binascii.Error):return dict(error='Invalid upload encoding'),400
            if len(raw)>limit or (pdf and not raw.startswith(b'%PDF-')):return dict(error='Invalid or oversized file'),400
            return delegate(op['endpoint'],user,method='POST',files={'file':(io.BytesIO(raw),filename,'application/pdf' if pdf else 'application/json')})
        return delegate(op['endpoint'],user,method=op['method'],view_args=params,
            **({'args':body} if op['method']=='GET' else {'body':body}))
