"""Regenerate both chat bridges from the server's fixed-operation definitions."""
import importlib.util
import json
import os
from pathlib import Path

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('agent_operations',root/'api/agent_operations.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
tools=[]
for op in module.OPERATIONS:
    tools.append(dict(name=op['name'],description=op['description']+' Requires '+op['scope']+'.',
        inputSchema=dict(type='object',properties=op['properties'],required=op['required'],additionalProperties=False),
        annotations=dict(readOnlyHint=op['method']=='GET' or op['name'] in ('psa_find_schools','psa_place_details','psa_plan_visits'),destructiveHint=op['method']=='DELETE' or op['name']=='psa_delete_schools',openWorldHint=False),
        method='POST',path='/operations/'+op['name']))
tools.append(dict(name='psa_capabilities',description='Check operation availability, delegated permissions and human-only controls for this connection.',inputSchema=dict(type='object',properties={},required=[],additionalProperties=False),annotations=dict(readOnlyHint=True,destructiveHint=False,openWorldHint=False),method='GET',path='/capabilities'))
tools.append(dict(name='psa_prepare_reply',description='Prepare a threaded reply for private human review. Requires outreach:prepare. Never approves or sends; execute the approved draft with psa_execute_approved_outreach.',inputSchema=dict(type='object',properties={'email_id':module.ID,'subject':module.S,'message':module.S},required=['email_id','subject','message'],additionalProperties=False),annotations=dict(readOnlyHint=False,destructiveHint=False,openWorldHint=False),method='POST',path='/outreach/reply-drafts'))
(root/'integrations/agent-operations.json').write_text(json.dumps(tools,indent=2)+'\n',encoding='utf-8')
tab_dir=os.environ.get('PSA_KAIROS_TAB_DIR')
if tab_dir:
    tab=Path(tab_dir)
    workflows=json.loads((tab/'workflows.json').read_text(encoding='utf-8'))
    names={t['name'] for t in tools}
    workflows=[t for t in workflows if t['name'] not in names]+tools
    (tab/'workflows.json').write_text(json.dumps(workflows,indent=2)+'\n',encoding='utf-8')
print('Generated',len(tools),'fixed business tools. Set PSA_KAIROS_TAB_DIR to update a source package too.')
