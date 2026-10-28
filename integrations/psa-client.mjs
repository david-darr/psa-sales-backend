// Fixed-path HTTPS client for the PSA Sales agent API. Node 22+, no dependencies.
const LOCAL_HOSTS=new Set(['localhost','127.0.0.1','[::1]']);
export function createPsaClient({url=process.env.PSA_API_URL,key=process.env.PSA_API_KEY,fetchImpl=fetch}={}){
 const base=new URL(url||'https://invalid.local');
 const secure=base.protocol==='https:'||(base.protocol==='http:'&&LOCAL_HOSTS.has(base.hostname));
 if(!secure||base.username||base.password||base.search||base.hash)throw new Error('PSA_API_URL must be an HTTPS API base URL ending in /api/agent/v1');
 if(!key||!/^psak_[0-9a-f]{64}$/.test(key))throw new Error('Set PSA_API_KEY to a PSA Sales API key');
 return async function request(method,path,body){
  // Paths are fixed by the bridge; never send the bearer token to a model-provided URL.
  if(!/^\/(me|team|pipeline|accounts|commissions|outreach(?:\/\d+)?|tasks(?:\/\d+)?|schools(?:\/assign|\/\d+(?:\/activities)?)?)$/.test(path))throw new Error('Invalid API path');
  const target=new URL(base.href.replace(/\/$/,'')+path);
  if(method==='GET'&&body)for(const [k,v] of Object.entries(body))if(v!==undefined&&v!==null)target.searchParams.set(k,String(v));
  const response=await fetchImpl(target,{method,redirect:'error',headers:{Authorization:'Bearer '+key,'Content-Type':'application/json'},...(method!=='GET'?{body:JSON.stringify(body||{})}:{}),signal:AbortSignal.timeout(30000)});
  let data;try{data=await response.json()}catch{data={}}
  if(!response.ok)throw new Error(`PSA Sales ${response.status}: ${data.error||'Request failed'}`);
  return data;
 };
}
