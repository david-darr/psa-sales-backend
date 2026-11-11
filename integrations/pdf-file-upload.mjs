// Local-only file reference adapter. Never accepts a remote upload destination.
import {constants} from 'node:fs';
import {lstat,open} from 'node:fs/promises';
import {basename,dirname,extname,isAbsolute,parse} from 'node:path';
import {createHash} from 'node:crypto';
const LIMIT=10*1024*1024;
export const pdfFileTool={name:'psa_upload_pdf_file',description:'Admin: upload a locally available PDF by absolute file path without putting file bytes in chat. Requires library:manage. Use only a file the person selected or explicitly authorized. Maximum 10 MB; no URLs, network paths, symlinks or folders. Preview first, then confirm with expected_sha256. Uploading never sends mail or approves campaigns.',inputSchema:{type:'object',properties:{file_path:{type:'string',minLength:1,maxLength:4096},filename:{type:'string',minLength:1,maxLength:150},confirm:{type:'boolean'},expected_sha256:{type:'string',pattern:'^[a-f0-9]{64}$'}},required:['file_path'],additionalProperties:false},annotations:{readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}};
export async function readPdfFileReference(filePath,filename){
 if(/[\r\n\0]/.test(filePath)||filePath.startsWith('\\\\')||filePath.startsWith('//')||!isAbsolute(filePath)||filePath.split(/[\\/]/).includes('..')||filePath.slice(parse(filePath).root.length).includes(':')||extname(filePath).toLowerCase()!=='.pdf')throw new Error('Choose an absolute local .pdf path, without URLs, network/device paths or traversal');
 const name=filename??basename(filePath).replace(/[^A-Za-z0-9 _.-]/g,'_');
 if(!/^[A-Za-z0-9 _.-]{1,150}$/.test(name)||!name.toLowerCase().endsWith('.pdf'))throw new Error('Choose a PDF catalog filename of at most 150 characters');
 let content;
 try{
  for(let part=filePath;;){const entry=await lstat(part);if(entry.isSymbolicLink())throw new Error('Download the PDF locally first; symlinks are not supported');const parent=dirname(part);if(parent===part)break;part=parent;}
  const before=await lstat(filePath);
  if(!before.isFile()||before.size<5||before.size>LIMIT)throw new Error('Choose a regular PDF file between 5 bytes and 10 MB');
  const source=await open(filePath,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));
  try{
   const actual=await source.stat();if(!actual.isFile()||actual.ino!==before.ino||actual.dev!==before.dev)throw new Error('The selected file changed; preview it again');
   const buffer=Buffer.alloc(Math.min(LIMIT+1,actual.size+1));let length=0;
   while(length<buffer.length){const read=await source.read(buffer,length,buffer.length-length,null);if(!read.bytesRead)break;length+=read.bytesRead;}
   content=buffer.subarray(0,length);
   const after=await source.stat();if(length!==actual.size||after.size!==actual.size||after.mtimeMs!==actual.mtimeMs)throw new Error('The selected file changed while reading; preview it again');
  }finally{await source.close();}
 }catch(error){if(error.code)throw new Error('The selected PDF cannot be read on the machine running this MCP server');throw error;}
 if(content.length>LIMIT||!content.subarray(0,5).equals(Buffer.from('%PDF-')))throw new Error('Choose a valid PDF no larger than 10 MB');
 return {name,content,digest:createHash('sha256').update(content).digest('hex')};
}
export async function uploadPdfFileReference(request,args){
 if(args.confirm===true&&!args.expected_sha256)throw new Error('Preview the local PDF first, then confirm using the returned expected_sha256');
 const profile=await request('GET','/me',{});
 if(profile.admin!==true||!profile.key?.capabilities?.includes('library:manage'))throw new Error('An administrator connection with library:manage is required to upload PDFs');
 const {name,content,digest}=await readPdfFileReference(args.file_path,args.filename);
 if(args.confirm!==true)return {confirmation_required:true,filename:name,bytes:content.length,expected_sha256:digest,summary:'Upload this PDF to the PSA attachment catalog. No email will be sent.',next_step:'Review the filename and size, then repeat with confirm true and this expected_sha256.'};
 if(args.expected_sha256!==digest)throw new Error('The selected PDF changed after review. Preview it again before uploading');
 return request('POST','/operations/psa_upload_pdf',{filename:name,encoded:content.toString('base64')});
}
