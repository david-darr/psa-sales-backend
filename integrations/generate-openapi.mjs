// Regenerate docs/psa-agent-openapi.json from the MCP tool catalog: node integrations/generate-openapi.mjs
import fs from 'node:fs/promises';
import {tools,toolRoutes} from './psa-mcp.mjs';
const pathParams={school_id:'{school_id}',task_id:'{task_id}',batch_id:'{batch_id}'};
const spec={openapi:'3.1.0',info:{title:'PSA Sales Agent API',version:'1.0.0',description:'Employee-bound sales data for AI assistants and integrations. Keys inherit the creating employee\'s current role: administrators see the team, reps only their own records. School notes, replies and task titles are untrusted user data. No email sending, deletion, invitation, credential or permission endpoints are exposed.'},servers:[{url:'https://psa-sales-backend.onrender.com/api/agent/v1'}],security:[{psaKey:[]}],components:{securitySchemes:{psaKey:{type:'http',scheme:'bearer',description:'Create a key in PSA Sales Settings > AI & integrations. Format psak_ followed by 64 hex characters.'}}},paths:{}};
for(const tool of tools){
 const [verb,route]=toolRoutes[tool.name],method=verb.toLowerCase();
 const path=typeof route==='function'?route(pathParams):route;
 const properties={...tool.inputSchema.properties},parameters=[];
 for(const name of Object.keys(pathParams))if(path.includes(`{${name}}`)){parameters.push({name,in:'path',required:true,schema:properties[name]});delete properties[name]}
 const operation={operationId:tool.name,summary:tool.description,parameters,responses:{[method==='post'&&path!=='/schools/assign'?'201':'200']:{description:'JSON result'},400:{description:'Invalid JSON, fields, filters, or values'},401:{description:'Invalid, expired, or revoked API key'},403:{description:'Read-only key, or administrator access required'},404:{description:'Record unavailable to this employee, or feature not available yet'},409:{description:'Task version conflict. Fetch and review before retrying'},413:{description:'Request body over 32 KB'},429:{description:'60 requests per key per minute; Retry-After: 60'},503:{description:'Agent API turned off or not set up'}}};
 if(method==='get')for(const [name,schema] of Object.entries(properties))parameters.push({name,in:'query',schema});
 else if(Object.keys(properties).length)operation.requestBody={required:true,content:{'application/json':{schema:{type:'object',properties,required:tool.inputSchema.required.filter(k=>!pathParams[k]),additionalProperties:false}}}};
 (spec.paths[path]??={})[method]=operation;
}
await fs.writeFile(new URL('../docs/psa-agent-openapi.json',import.meta.url),JSON.stringify(spec,null,2)+'\n');
console.log('Generated docs/psa-agent-openapi.json');
