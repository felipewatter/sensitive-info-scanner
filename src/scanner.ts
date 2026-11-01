import {lstat, readdir, readFile, realpath} from 'node:fs/promises';
import path from 'node:path';
import {defaultPatterns, hasSensitiveFilename, type LiteralPattern, type Severity} from './patterns';

export type Finding = {path: string; line: number | null; rule: string; severity: Severity};
export type ScanOptions = {
  maxFileBytes?: number;
  maxFiles?: number;
  maxDepth?: number;
  maxTotalBytes?: number;
  customPatterns?: LiteralPattern[];
};
export type ScanResult = {
  root: string;
  scannedFiles: number;
  skippedBinary: number;
  skippedSymlinks: number;
  skippedDirectories: number;
  scannedBytes: number;
  findings: Finding[];
};
const SKIP_DIRS = new Set(['.git','node_modules','vendor','.next','dist','build','coverage','.cache','.turbo','.venv','venv','__pycache__']);
const MAX_FINDINGS = 10000;
export async function scanDirectory(input: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const maxFileBytes=opts.maxFileBytes ?? 1024*1024;
  const maxFiles=opts.maxFiles ?? 20000;
  const maxDepth=opts.maxDepth ?? 24;
  const maxTotalBytes=opts.maxTotalBytes ?? 64*1024*1024;
  if (![maxFileBytes,maxFiles,maxDepth,maxTotalBytes].every(Number.isSafeInteger) ||
     maxFileBytes < 1024 || maxFileBytes > 8*1024*1024 || maxFiles < 1 || maxFiles > 100000 ||
     maxDepth < 0 || maxDepth > 64 || maxTotalBytes < maxFileBytes || maxTotalBytes > 512*1024*1024)
     throw Error('Invalid scan limits');
  const root = path.resolve(input);
  const stat = await lstat(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error('Scan root must be a real directory');
  const trueRoot=await realpath(root);
  const result: ScanResult={root,scannedFiles:0,skippedBinary:0,skippedSymlinks:0,
    skippedDirectories:0,scannedBytes:0,findings:[]};
  const append=(relative:string,line:number|null,rule:string,severity:Severity)=>{
    if(result.findings.length>=MAX_FINDINGS)throw Error('Finding limit reached: scan incomplete');
    result.findings.push({path:relative.split(path.sep).join('/'),line,rule,severity});
  };
  async function visit(directory:string,depth:number):Promise<void>{
    if(depth>maxDepth)throw Error('Maximum directory depth reached: scan incomplete');
    const entries=(await readdir(directory,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute=path.join(directory,entry.name);
      const relative=path.relative(root,absolute);
      // lstat prevents following symlinked files and directories.
      const st=await lstat(absolute);
      if(st.isSymbolicLink()){result.skippedSymlinks++;continue;}
      if(st.isDirectory()){
        if(SKIP_DIRS.has(entry.name)){result.skippedDirectories++;continue;}
        await visit(absolute,depth+1);
        continue;
      }
      if(!st.isFile()){continue;}
      if(result.scannedFiles>=maxFiles)throw Error('Maximum file count reached: scan incomplete');
      if(st.size>maxFileBytes)throw Error('File exceeds maxFileBytes: scan incomplete ('+relative+')');
      if(result.scannedBytes+st.size>maxTotalBytes)throw Error('Maximum aggregate byte count reached: scan incomplete');
      // Revalidate realpath to block a pre-existing link outside root.
      const actual=await realpath(absolute);
      if(actual!==trueRoot && !actual.startsWith(trueRoot+path.sep))
        throw Error('File resolved outside scan root');
      const data=await readFile(absolute);
      if(data.length>maxFileBytes || result.scannedBytes+data.length>maxTotalBytes)
        throw Error('File size changed during scan: scan incomplete');
      result.scannedFiles++;
      result.scannedBytes+=data.length;
      if(hasSensitiveFilename(entry.name))append(relative,null,'sensitive-filename','high');
      // Treat binary content as opaque, except name-based detection.
      if(data.subarray(0,4096).includes(0)){result.skippedBinary++;continue;}
      const lines=data.toString('utf8').split(/\r?\n/);
      const perFile=new Set<string>();
      for(let i=0;i<lines.length;i++){
        const text=lines[i]!;
        for(const p of defaultPatterns){
          if(!p.regex.test(text))continue;
          const dedupe=p.id+'|'+i;
          if(!perFile.has(dedupe)){append(relative,i+1,p.id,p.severity);perFile.add(dedupe);}
        }
        for(const p of opts.customPatterns??[]){
          const match=p.caseSensitive?text.includes(p.literal):text.toLowerCase().includes(p.literal.toLowerCase());
          if(!match)continue;
          const dedupe=p.id+'|'+i;
          if(!perFile.has(dedupe)){append(relative,i+1,p.id,'medium');perFile.add(dedupe);}
        }
      }
    }
  }
  await visit(root,0);
  result.findings.sort((a,b)=>a.path.localeCompare(b.path)||(a.line??0)-(b.line??0)||a.rule.localeCompare(b.rule));
  return result;
}

/** Compatibility wrapper from the v1.0.0 module (redacted findings only). */
export async function scanDir(dirPath: string):Promise<string[]> {
  const r=await scanDirectory(dirPath);
  return r.findings.map(f=>f.rule+' in '+f.path+(f.line===null?'':':'+f.line));
}
