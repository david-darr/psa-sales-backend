// AI harnesses can invoke this CLI with credentials supplied through private env.
import {createPsaClient} from './psa-client.mjs';
import {tools,callTool} from './psa-mcp.mjs';
import {readFileSync,statSync} from 'node:fs';
import {basename} from 'node:path';
try{
 const [name,raw='{}',filename]=process.argv.slice(2);
 if(name==='--list')console.log(JSON.stringify(tools,null,2));
 else{
  if(!name)throw new Error('Usage: node integrations/psa-cli.mjs --list | <tool_name> [JSON arguments]');
  let args;
  if(raw==='--file'){
   if(!['psa_upload_pdf','psa_upload_templates'].includes(name)||!filename)throw new Error('--file is only for uploading a chosen PDF or template JSON');
   const maximum=name==='psa_upload_pdf'?10*1024*1024:1024*1024;
   if(!statSync(filename).isFile()||statSync(filename).size>maximum)throw new Error('Chosen upload is not a file or exceeds the upload limit');
   args={filename:basename(filename),encoded:readFileSync(filename).toString('base64')};
  }else args=JSON.parse(raw);
  console.log(JSON.stringify(await callTool(createPsaClient(),name,args),null,2));
 }
}catch(e){console.error(e.message);process.exitCode=1}
