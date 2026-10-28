// AI harnesses can invoke this CLI with credentials supplied through private env.
import {createPsaClient} from './psa-client.mjs';
import {tools,callTool} from './psa-mcp.mjs';
try{
 const [name,raw='{}']=process.argv.slice(2);
 if(name==='--list')console.log(JSON.stringify(tools,null,2));
 else{
  if(!name)throw new Error('Usage: node integrations/psa-cli.mjs --list | <tool_name> [JSON arguments]');
  console.log(JSON.stringify(await callTool(createPsaClient(),name,JSON.parse(raw)),null,2));
 }
}catch(e){console.error(e.message);process.exitCode=1}
