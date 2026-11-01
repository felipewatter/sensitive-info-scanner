#!/usr/bin/env node
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {scanDirectory, type ScanResult} from '../src/scanner';
import {validateLiteralPatterns, type LiteralPattern} from '../src/patterns';
export type CLIOptions={
  path:string;format:'text'|'json';maxFileBytes:number;maxFiles:number;maxDepth:number;
  maxTotalBytes:number;patternFile?:string
};
const HELP = [
'Sensitive Info Scanner v1.1.0 — local scanner, no network',
'Usage: sensitive-info-scanner <path> [options]',
'  --path DIR                 Directory to scan (alternative to positional path)',
'  --format text|json         Default text',
'  --pattern-file FILE        JSON file containing 1..20 custom LITERAL patterns',
'  --max-file-bytes NUM       Limit each file (1024..8388608, default 1048576)',
'  --max-files NUM            Maximum files (1..100000, default 20000)',
'  --max-depth NUM            Maximum nested depth (0..64, default 24)',
'  --max-total-bytes NUM      Total byte budget (default 67108864, max 536870912)',
'  --help / --version         Help and version',
'Codes: 0=clean, 1=possible sensitive material, 2=error/partial scan.',
'Output only contains rule IDs, paths and line numbers. No secret values.'
].join('\n');
const choices = ['--path','--format','--pattern-file','--max-file-bytes','--max-files','--max-depth','--max-total-bytes'];
function numberOption(input:string, min:number,max:number):number{
  if(!/^(0|[1-9][0-9]*)$/.test(input))throw Error('Invalid numeric option');
  const n=Number(input);
  if(!Number.isSafeInteger(n)||n<min||n>max)throw Error('Numeric option out of range');
  return n;
}
export function parseArgs(args:readonly string[]):CLIOptions|'help'|'version'{
  const options:CLIOptions={path:'',format:'text',maxFileBytes:1048576,maxFiles:20000,maxDepth:24,maxTotalBytes:67108864};
  for(let i=0;i<args.length;i++){
    const raw=args[i]!;
    const idx=raw.indexOf('=');
    const flag=idx<0?raw:raw.slice(0,idx);
    if(flag==='--help'||flag==='-h')return 'help';
    if(flag==='--version'||flag==='-v')return 'version';
    if(!flag.startsWith('--')){
      if(options.path)throw Error('Only one directory may be selected');
      options.path=raw;continue;
    }
    if(!choices.includes(flag))throw Error('Unknown option');
    const v=idx>=0?raw.slice(idx+1):args[++i];
    if(!v || (idx<0 && v.startsWith('--')))throw Error('Missing option value');
    switch(flag){
      case '--path':if(options.path)throw Error('Directory already selected');options.path=v;break;
      case '--format':if(v!=='json'&&v!=='text')throw Error('Invalid output format');options.format=v;break;
      case '--pattern-file':options.patternFile=v;break;
      case '--max-file-bytes':options.maxFileBytes=numberOption(v,1024,8388608);break;
      case '--max-files':options.maxFiles=numberOption(v,1,100000);break;
      case '--max-depth':options.maxDepth=numberOption(v,0,64);break;
      case '--max-total-bytes':options.maxTotalBytes=numberOption(v,1024,536870912);break;
    }
  }
  if(!options.path)throw Error('Directory path is required');
  if(options.maxTotalBytes<options.maxFileBytes)throw Error('Total bytes must be >= max file bytes');
  return options;
}
function render(result:ScanResult,format:'text'|'json'):string{
  // Deliberately avoid snippets, matching substrings, and secrets.
  const {root,...safe}=result;
  if(format==='json')return JSON.stringify({schemaVersion:1,status:safe.findings.length?'findings':'clean',...safe},null,2);
  const lines=['Sensitive Info Scanner v1.1.0',
    'Files scanned: '+safe.scannedFiles,
    'Binary files skipped: '+safe.skippedBinary,
    'Symbolic links skipped: '+safe.skippedSymlinks,
    'Ignored directories: '+safe.skippedDirectories,
    'Potential findings: '+safe.findings.length];
  for(const f of safe.findings){
    // Paths may contain terminal control chars; do not print them raw.
    lines.push('['+f.severity.toUpperCase()+'] '+f.rule+' @ '+f.path.replace(/[\x00-\x1f\x7f-\x9f]/g,'?')+(f.line===null?'':':'+f.line));
  }
  return lines.join('\n');
}
export async function main(args:readonly string[]=process.argv.slice(2)):Promise<number>{
  let o:ReturnType<typeof parseArgs>;
  try{o=parseArgs(args);}catch{console.error('Sensitive Info Scanner: invalid arguments. See --help.');return 2;}
  if(o==='help'){console.log(HELP);return 0;}
  if(o==='version'){console.log('1.1.0');return 0;}
  try{
    let customPatterns:LiteralPattern[]=[];
    if(o.patternFile){
      const src=await readFile(path.resolve(o.patternFile),'utf8');
      if(src.length>16384)throw Error('Custom pattern file too large');
      customPatterns=validateLiteralPatterns(JSON.parse(src));
    }
    const result=await scanDirectory(o.path,{maxFileBytes:o.maxFileBytes,maxFiles:o.maxFiles,
      maxDepth:o.maxDepth,maxTotalBytes:o.maxTotalBytes,customPatterns});
    console.log(render(result,o.format));
    return result.findings.length>0?1:0;
  }catch{
    // Some OS error messages embed filenames or secrets; do not echo raw errors.
    console.error('Sensitive Info Scanner: scan failed or incomplete; refusing to report clean.');
    return 2;
  }
}
if(require.main===module)void main().then(code=>{process.exitCode=code;});
