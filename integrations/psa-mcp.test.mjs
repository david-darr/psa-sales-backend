// node --test integrations/psa-mcp.test.mjs : bridge checks with a fake fetch, no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createPsaClient} from './psa-client.mjs';
import {tools,callTool,handleMessage} from './psa-mcp.mjs';

const KEY='psak_'+'a'.repeat(64);
function fake(status=200,data={ok:true}){
 const calls=[];
 const fetchImpl=async(url,init)=>{calls.push({url:String(url),init});return {ok:status<400,status,json:async()=>data}};
 return {calls,request:createPsaClient({url:'https://psa.example.test/api/agent/v1',key:KEY,fetchImpl})};
}

test('client refuses insecure URLs and malformed keys',()=>{
 assert.throws(()=>createPsaClient({url:'http://psa.example.test/api/agent/v1',key:KEY}),/HTTPS/);
 assert.throws(()=>createPsaClient({url:'https://psa.example.test/api/agent/v1',key:'tbk_x'}),/PSA_API_KEY/);
 assert.ok(createPsaClient({url:'http://localhost:5000/api/agent/v1',key:KEY}));
});

test('tools map to fixed paths with the key only in the header',async()=>{
 const {calls,request}=fake();
 await callTool(request,'psa_schools',{q:'maple',stage:'contacted,meeting',limit:5});
 await callTool(request,'psa_update_task',{task_id:4,version:2,status:'completed'});
 await callTool(request,'psa_log_activity',{school_id:9,kind:'call',detail:'Spoke'});
 assert.equal(calls[0].url,'https://psa.example.test/api/agent/v1/schools?q=maple&stage=contacted%2Cmeeting&limit=5');
 assert.equal(calls[0].init.method,'GET');
 assert.equal(calls[1].url,'https://psa.example.test/api/agent/v1/tasks/4');
 assert.deepEqual(JSON.parse(calls[1].init.body),{version:2,status:'completed'});
 assert.equal(calls[2].url,'https://psa.example.test/api/agent/v1/schools/9/activities');
 for(const call of calls){assert.equal(call.init.redirect,'error');assert.ok(!call.url.includes(KEY));assert.equal(call.init.headers.Authorization,'Bearer '+KEY)}
});

test('arguments are validated before any request',async()=>{
 const {calls,request}=fake();
 await assert.rejects(callTool(request,'psa_school',{school_id:'../me'}),/Invalid record ID/);
 await assert.rejects(callTool(request,'psa_school',{}),/Invalid tool arguments/);
 await assert.rejects(callTool(request,'psa_tasks',{url:'https://evil.test'}),/Invalid tool arguments/);
 await assert.rejects(callTool(request,'psa_send_email',{}),/Unknown tool/);
 await assert.rejects(request('GET','/../admin'),/Invalid API path/);
 assert.equal(calls.length,0);
});

test('API errors surface status and message',async()=>{
 const {request}=fake(409,{error:'This task changed. Refresh before trying again.'});
 await assert.rejects(callTool(request,'psa_update_task',{task_id:1,version:1,status:'completed'}),/PSA Sales 409: This task changed/);
});

test('MCP protocol: initialize, list, call, errors',async()=>{
 const {request}=fake(200,{id:1});
 const init=await handleMessage({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18'}},request);
 assert.equal(init.result.protocolVersion,'2025-06-18');
 assert.match(init.result.instructions,/untrusted/);
 const listed=await handleMessage({jsonrpc:'2.0',id:2,method:'tools/list'},request);
 assert.equal(listed.result.tools.length,tools.length);
 assert.ok(tools.filter(t=>!t.annotations.readOnlyHint).every(t=>/write key|Requires (?:write|schools:import|outreach:prepare|library:manage|commissions:manage|team:manage|separately delegated outreach:send)/i.test(t.description)));
 assert.ok(!tools.some(t=>/send/.test(t.name)));
 const called=await handleMessage({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'psa_connection',arguments:{}}},request);
 assert.deepEqual(JSON.parse(called.result.content[0].text),{id:1});
 const failed=await handleMessage({jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'nope',arguments:{}}},request);
 assert.equal(failed.result.isError,true);
 assert.equal(await handleMessage({jsonrpc:'2.0',method:'notifications/initialized'},request),null);
 assert.equal((await handleMessage({jsonrpc:'2.0',id:5,method:'resources/list'},request)).error.code,-32601);
});

test('approval tools never expose human approval or message overrides on execution',async()=>{
 const {calls,request}=fake();
 await callTool(request,'psa_prepare_outreach',{kind:'custom',school_ids:[1],subject:'Preview',body:'Hello'});
 await callTool(request,'psa_execute_approved_outreach',{draft_id:'1234-safe'});
 await callTool(request,'psa_import_commit',{import_id:'safe_import',file_hash:'a'.repeat(64)});
 await callTool(request,'psa_reply_chain',{email_id:12});
 assert.equal(calls[0].url,'https://psa.example.test/api/agent/v1/outreach/drafts');
 assert.equal(calls[1].url,'https://psa.example.test/api/agent/v1/outreach/drafts/1234-safe/execute');
 assert.deepEqual(JSON.parse(calls[1].init.body),{});
 assert.equal(calls[2].url,'https://psa.example.test/api/agent/v1/imports/safe_import/commit');
 assert.equal(calls[3].url,'https://psa.example.test/api/agent/v1/outreach/replies/12');
 await assert.rejects(callTool(request,'psa_execute_approved_outreach',{draft_id:'../approve'}),/Invalid record ID/);
 await assert.rejects(callTool(request,'psa_execute_approved_outreach',{draft_id:'safe',sender_id:2}),/Invalid tool arguments/);
 await assert.rejects(callTool(request,'psa_approve_outreach',{draft_id:'safe'}),/Unknown tool/);
 await assert.rejects(request('POST','/outreach/drafts/safe/approve',{}),/Invalid API path/);
});


test('campaign tools prepare/read/stop fixed scope but cannot approve or resume',async()=>{
 const {calls,request}=fake();
 await callTool(request,'psa_prepare_campaign',{name:'Winter',school_ids:[1,2],template_id:3,template_revision:1,daily_cap:10,start_date:'2026-11-09',end_date:'2026-12-20'});
 await callTool(request,'psa_campaign_plan',{plan_id:'test-plan'});
 await callTool(request,'psa_stop_campaign',{plan_id:'test-plan',revision:2,action:'pause'});
 assert.equal(calls[0].url,'https://psa.example.test/api/agent/v1/outreach/campaign-plans');
 assert.equal(calls[1].url,'https://psa.example.test/api/agent/v1/outreach/campaign-plans/test-plan');
 assert.deepEqual(JSON.parse(calls[2].init.body),{revision:2,action:'pause'});
 await assert.rejects(callTool(request,'psa_campaign_plan',{plan_id:'../admin'}),/Invalid record ID/);
 await assert.rejects(request('POST','/outreach/campaign-plans/test-plan/approve',{}),/Invalid API path/);
 await assert.rejects(request('POST','/outreach/campaign-plans/test-plan/resume',{}),/Invalid API path/);
 assert.ok(!tools.some(t=>t.name==='psa_approve_campaign'));
});

test('business operations preserve IDs in bounded bodies and reject unknown fields',async()=>{
 const {calls,request}=fake();
 await callTool(request,'psa_edit_contact',{school_id:8,link_id:9,version:1,contact_version:2,name:'Taylor'});
 await callTool(request,'psa_find_schools',{address:'12345',radius_km:12.5});
 await callTool(request,'psa_capabilities',{});
 assert.equal(calls[0].url,'https://psa.example.test/api/agent/v1/operations/psa_edit_contact');
 assert.deepEqual(JSON.parse(calls[0].init.body),{school_id:8,link_id:9,version:1,contact_version:2,name:'Taylor'});
 assert.equal(calls[1].url,'https://psa.example.test/api/agent/v1/operations/psa_find_schools');
 assert.equal(calls[2].init.method,'GET');
 await assert.rejects(callTool(request,'psa_edit_contact',{school_id:-1,link_id:9,version:1,contact_version:2}),/Invalid/);
 await assert.rejects(callTool(request,'psa_find_schools',{address:'12345',radius_km:NaN}),/Invalid/);
 await assert.rejects(callTool(request,'psa_create_template',{name:'Test',kind:'initial',audience:'general',subject:'Test',body:'Body',access_token:'secret'}),/Invalid/);
 await assert.rejects(request('POST','/operations/arbitrary',{}),/Invalid API path/);
 await assert.rejects(request('GET','/operations/psa_upload_pdf',{}),/Invalid API path/);
 assert.equal(calls.length,3);
});

test('uploads exceed the old 64KB limit and replies stay preparation-only',async()=>{
 const {calls,request}=fake();
 const encoded=Buffer.from('%PDF-1.4\n'+'0'.repeat(70000)).toString('base64');
 await callTool(request,'psa_upload_pdf',{filename:'Chosen flyer.pdf',encoded});
 assert.equal(calls[0].url,'https://psa.example.test/api/agent/v1/operations/psa_upload_pdf');
 assert.equal(JSON.parse(calls[0].init.body).encoded,encoded);
 await callTool(request,'psa_prepare_reply',{email_id:12,subject:'Re: Hello',message:'Thanks'});
 assert.equal(calls[1].url,'https://psa.example.test/api/agent/v1/outreach/reply-drafts');
 assert.deepEqual(JSON.parse(calls[1].init.body),{email_id:12,subject:'Re: Hello',message:'Thanks'});
 assert.equal(tools.find(t=>t.name==='psa_delete_schools').annotations.destructiveHint,true);
 assert.equal(tools.find(t=>t.name==='psa_find_schools').annotations.readOnlyHint,true);
});


test('local file reference uploads a 2.9 MB flyer without base64 in model arguments or results',async()=>{
 const {mkdtemp,writeFile,rm}=await import('node:fs/promises');
 const {tmpdir}=await import('node:os');const {join}=await import('node:path');const {createHash}=await import('node:crypto');
 const folder=await mkdtemp(join(tmpdir(),'psa-pdf-ref-'));
 const calls=[];
 const request=async(method,path,body)=>{calls.push({method,path,body});if(path==='/me')return {admin:true,key:{capabilities:['library:manage']}};assert.equal(path,'/operations/psa_upload_pdf');return {id:createHash('sha256').update(Buffer.from(body.encoded,'base64')).digest('hex'),name:body.filename,bytes:Buffer.from(body.encoded,'base64').length};};
 try{
  const path=join(folder,'Sponsor flyer.pdf'),raw=Buffer.concat([Buffer.from('%PDF-1.4\n'),Buffer.alloc(2_900_000,65),Buffer.from('\n%%EOF')]);await writeFile(path,raw);
  const preview=await callTool(request,'psa_upload_pdf_file',{file_path:path});
  assert.equal(preview.confirmation_required,true);assert.equal(preview.bytes,raw.length);assert.ok(JSON.stringify(preview).length<1000);assert.equal(calls.filter(c=>c.method==='POST').length,0);
  await assert.rejects(callTool(request,'psa_upload_pdf_file',{file_path:path,confirm:true}),/Preview/);
  const saved=await callTool(request,'psa_upload_pdf_file',{file_path:path,confirm:true,expected_sha256:preview.expected_sha256});
  assert.equal(saved.id,createHash('sha256').update(raw).digest('hex'));assert.equal(saved.bytes,raw.length);assert.ok(!Object.hasOwn(saved,'encoded'));assert.equal(calls.filter(c=>c.method==='POST').length,1);
  await writeFile(path,'%PDF-1.4\nChanged\n%%EOF');
  await assert.rejects(callTool(request,'psa_upload_pdf_file',{file_path:path,confirm:true,expected_sha256:preview.expected_sha256}),/changed after review/);
  assert.equal(calls.filter(c=>c.method==='POST').length,1);
 }finally{await cleanPdfFixture(folder);}
});

test('file reference rejects unsupported paths, non-PDFs, oversize files and unprivileged keys',async()=>{
 const {mkdtemp,writeFile,truncate,mkdir,rm}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const folder=await mkdtemp(join(tmpdir(),'psa-pdf-invalid-'));
 const request=async()=>({admin:true,key:{capabilities:['library:manage']}});
 try{
  const path=join(folder,'Bad.pdf');await writeFile(path,'Not a PDF');await mkdir(join(folder,'Folder.pdf'));
  for(const value of ['relative.pdf','https://evil.test/a.pdf',path,join(folder,'Missing.pdf'),join(folder,'Folder.pdf')])await assert.rejects(callTool(request,'psa_upload_pdf_file',{file_path:value}));
  await writeFile(path,'%PDF-');await truncate(path,10*1024*1024+1);
  await assert.rejects(callTool(request,'psa_upload_pdf_file',{file_path:path}),/10 MB/);
  await assert.rejects(callTool(async()=>({admin:false,key:{capabilities:['library:manage']}}),'psa_upload_pdf_file',{file_path:join(folder,'Missing.pdf')}),/administrator/);
  await assert.rejects(callTool(async()=>({admin:true,key:{capabilities:[]}}),'psa_upload_pdf_file',{file_path:join(folder,'Missing.pdf')}),/library:manage/);
 }finally{await cleanPdfFixture(folder);}
});

test('file reference rejects a linked parent directory',async()=>{
 const {mkdtemp,mkdir,writeFile,symlink,rm}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const folder=await mkdtemp(join(tmpdir(),'psa-pdf-links-'));
 try{
  const target=join(folder,'target'),link=join(folder,'linked');await mkdir(target);await writeFile(join(target,'Flyer.pdf'),'%PDF-1.4\n%%EOF');
  await symlink(target,link,process.platform==='win32'?'junction':'dir');
  await assert.rejects(callTool(async()=>({admin:true,key:{capabilities:['library:manage']}}),'psa_upload_pdf_file',{file_path:join(link,'Flyer.pdf')}),/symlinks/);
 }finally{await cleanPdfFixture(folder);}
});

async function cleanPdfFixture(folder){
 const {resolve,dirname,basename}=await import('node:path');const {tmpdir}=await import('node:os');const {rm}=await import('node:fs/promises');
 const resolved=resolve(folder);assert.equal(dirname(resolved),resolve(tmpdir()));assert.ok(basename(resolved).startsWith('psa-pdf-'));
 await rm(resolved,{recursive:true,force:true});
}
