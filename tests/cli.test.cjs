const {test}=require('node:test');
const assert=require('node:assert/strict');
const {mkdtempSync,writeFileSync,rmSync}=require('node:fs');
const {tmpdir}=require('node:os');
const {join}=require('node:path');
const {spawnSync}=require('node:child_process');
const {parseArgs}=require('../dist/bin/index.js');
const cli=join(__dirname,'..','dist','bin','index.js');
const run=args=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',timeout:10000});
const fixture=()=>mkdtempSync(join(tmpdir(),'sis-cli-'));
test('CLI argument validation and defaults',()=>{
  const opts=parseArgs(['/tmp/target','--format=json','--max-depth','3']);
  assert.equal(opts.path,'/tmp/target');assert.equal(opts.format,'json');assert.equal(opts.maxDepth,3);
  for(const a of [[],['--max-files','0','target'],['--format','xml','target'],
    ['target','other'],['target','--unrecognized'],['target','--max-file-bytes','1']])
    assert.throws(()=>parseArgs(a));
});
test('CLI help and version do not scan',()=>{
  assert.equal(run(['--help']).status,0);
  assert.match(run(['--version']).stdout,/1.1.0/);
});
test('CLI exits zero on clean scan',()=>{
  const root=fixture();
  try{writeFileSync(join(root,'ok.txt'),'hello');
    const r=run([root,'--format','json']);assert.equal(r.status,0,r.stderr);
    const data=JSON.parse(r.stdout);assert.equal(data.status,'clean');assert.equal(data.findings.length,0);
    assert.ok(!('root' in data));
  }finally{rmSync(root,{recursive:true,force:true});}
});
test('CLI exits one on secret, reports no matched text',()=>{
  const root=fixture();
  const secret='ghp_'+'Q'.repeat(36);
  try{writeFileSync(join(root,'suspicious.txt'),'\\n'+secret);
    const r=run([root,'--format','json']);assert.equal(r.status,1,r.stderr);
    const data=JSON.parse(r.stdout);assert.equal(data.status,'findings');
    assert.equal(data.findings[0].rule,'github-token');assert.equal(data.findings[0].line,2);
    assert.equal(r.stdout.includes(secret),false);
  }finally{rmSync(root,{recursive:true,force:true});}
});
test('CLI exits two on truncated scan and does not produce clean JSON',()=>{
  const root=fixture();
  try{writeFileSync(join(root,'huge.txt'),'a'.repeat(5000));
    const r=run([root,'--max-file-bytes','1024','--format','json']);
    assert.equal(r.status,2);assert.equal(r.stdout.trim(),'');
  }finally{rmSync(root,{recursive:true,force:true});}
});
test('custom literal pattern file can identify project-specific secret markers',()=>{
  const root=fixture();
  try{
    writeFileSync(join(root,'s.txt'),'masked key XYZZY-AUTH-FLAG-879');
    const patterns=join(root,'patterns.json');
    writeFileSync(patterns,JSON.stringify({patterns:[{id:'auth-marker',literal:'XYZZY-AUTH-FLAG-879'}]}));
    const r=run([root,'--pattern-file',patterns,'--format','json']);assert.equal(r.status,1,r.stderr);
    assert.equal(JSON.parse(r.stdout).findings[0].rule,'custom-auth-marker');
  }finally{rmSync(root,{recursive:true,force:true});}
});
