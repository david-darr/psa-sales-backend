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
 assert.ok(tools.filter(t=>!t.annotations.readOnlyHint).every(t=>/write key/i.test(t.description)));
 assert.ok(!tools.some(t=>/send/.test(t.name)));
 const called=await handleMessage({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'psa_connection',arguments:{}}},request);
 assert.deepEqual(JSON.parse(called.result.content[0].text),{id:1});
 const failed=await handleMessage({jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'nope',arguments:{}}},request);
 assert.equal(failed.result.isError,true);
 assert.equal(await handleMessage({jsonrpc:'2.0',method:'notifications/initialized'},request),null);
 assert.equal((await handleMessage({jsonrpc:'2.0',id:5,method:'resources/list'},request)).error.code,-32601);
});
