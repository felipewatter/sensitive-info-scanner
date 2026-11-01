const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {scanDirectory,scanDir} = require('../dist/src/scanner.js');
const {validateLiteralPatterns,hasSensitiveFilename} = require('../dist/src/patterns.js');
const make = () => fs.mkdtempSync(path.join(os.tmpdir(),'sis-scan-'));
const clean = root => fs.rmSync(root,{recursive:true,force:true});
const write = (root,p,value) => {fs.mkdirSync(path.dirname(path.join(root,p)),{recursive:true});fs.writeFileSync(path.join(root,p),value);};

test('finds AWS, GitHub, Slack, private keys and generic assignments with line numbers', async()=>{
  const root=make();
  const secrets=['AKIA'+'A'.repeat(16),'ghp_'+'B'.repeat(36),'xoxb-'+'C'.repeat(14),
    '-----BEGIN PRIVATE KEY-----','api_key = "'+'Z'.repeat(32)+'"'];
  try{
    write(root,'src/example.txt','safe\n'+secrets.join('\n')+'\n');
    const r=await scanDirectory(root);
    assert.equal(r.scannedFiles,1);
    assert.deepEqual(r.findings.map(f=>f.rule).sort(),[
      'aws-access-key','generic-secret-assignment','github-token','private-key-block','slack-token'
    ].sort());
    assert.equal(r.findings[0].line,2);
    const output=JSON.stringify(r);
    for(const s of secrets)assert.equal(output.includes(s),false,'Secret leaked to output');
    assert.equal(output.includes('src/example.txt'),true);
  }finally{clean(root);}
});
test('detects sensitive filenames without reading secret values into findings',async()=>{
  const root=make();
  try{
    write(root,'.env','SOME_PRIVATE_DATA_THAT_IS_NOT_LOGGED');
    write(root,'.env.example','EXAMPLE=placeholder');
    write(root,'id_ed25519','nonsensitive-test');
    write(root,'secrets.pem','placeholder');
    const r=await scanDirectory(root);
    const filenameFindings=r.findings.filter(x=>x.rule==='sensitive-filename');
    assert.equal(filenameFindings.length,3);
    assert.ok(filenameFindings.every(x=>x.line===null));
    assert.equal(JSON.stringify(r).includes('SOME_PRIVATE_DATA_THAT_IS_NOT_LOGGED'),false);
    assert.equal(hasSensitiveFilename('.env.example'),false);
  }finally{clean(root);}
});
test('does not recursively scan excluded dependency/build directories',async()=>{
  const root=make();
  try{
    for(const folder of ['node_modules','.git','dist','vendor','coverage']){
      write(root,folder+'/secret.txt','AKIA'+'K'.repeat(16));
    }
    write(root,'src/ok.txt','hello world');
    const r=await scanDirectory(root);
    assert.equal(r.findings.length,0);
    assert.equal(r.skippedDirectories,5);
    assert.equal(r.scannedFiles,1);
  }finally{clean(root);}
});
test('skips binary data without exposing contents',async()=>{
  const root=make();
  try{
    write(root,'asset.bin',Buffer.from([0,1,2,3,4]));
    const r=await scanDirectory(root);
    assert.equal(r.skippedBinary,1);
    assert.equal(r.findings.length,0);
  }finally{clean(root);}
});
test('does not follow symbolic links outside root', {skip:process.platform==='win32'},async()=>{
  const root=make(),outside=make();
  try{
    write(outside,'external.txt','AKIA'+'J'.repeat(16));
    fs.symlinkSync(outside,path.join(root,'linked'),'dir');
    fs.symlinkSync(path.join(outside,'external.txt'),path.join(root,'link.txt'),'file');
    const r=await scanDirectory(root);
    assert.equal(r.findings.length,0);
    assert.equal(r.skippedSymlinks,2);
  }finally{clean(root);clean(outside);}
});
test('rejects symlink root rather than scanning arbitrary external targets',{skip:process.platform==='win32'},async()=>{
  const root=make(),link=root+'-link';
  try{
    fs.symlinkSync(root,link,'dir');
    await assert.rejects(()=>scanDirectory(link),/real directory/);
  }finally{fs.rmSync(link,{force:true});clean(root);}
});
test('large file triggers explicit incomplete scan error',async()=>{
  const root=make();
  try{write(root,'large.txt','A'.repeat(5000));
    await assert.rejects(()=>scanDirectory(root,{maxFileBytes:1024}),/incomplete/);
  }finally{clean(root);}
});
test('maximum files and total byte budget refuse partial reports',async()=>{
  const root=make();
  try{
    write(root,'a.txt','A'.repeat(1024));
    write(root,'b.txt','B'.repeat(1024));
    await assert.rejects(()=>scanDirectory(root,{maxFiles:1}),/incomplete/);
    await assert.rejects(()=>scanDirectory(root,{maxTotalBytes:1500,maxFileBytes:1024}),/incomplete/);
  }finally{clean(root);}
});
test('maximum depth prevents silently omitted folders',async()=>{
  const root=make();
  try{
    write(root,'nested/secret.txt','A'.repeat(20));
    await assert.rejects(()=>scanDirectory(root,{maxDepth:0}),/incomplete/);
  }finally{clean(root);}
});
test('custom literal patterns match without interpretation as regular expressions',async()=>{
  const root=make();
  try{
    write(root,'test.txt','warning: [secret] and XYZ-protected-value');
    const patterns=validateLiteralPatterns({patterns:[
      {id:'literal-square-bracket',literal:'[secret]'},
      {id:'custom-sensitive',literal:'xyz-protected-value'}
    ]});
    const r=await scanDirectory(root,{customPatterns:patterns});
    assert.deepEqual(r.findings.map(f=>f.rule),['custom-custom-sensitive','custom-literal-square-bracket']);
  }finally{clean(root);}
});
test('custom patterns reject invalid JSON structures or duplicate names',()=>{
  for(const bad of [null,[],{patterns:[]},{patterns:[{id:'foo',literal:'a'}]},
    {patterns:[{id:'foo',literal:'test'},{id:'foo',literal:'other'}]},
    {patterns:[{id:'foo',literal:'oops\nnewline'}]},
    {patterns:[{id:'foo',literal:'literal',caseSensitive:'yes'}]}])
    assert.throws(()=>validateLiteralPatterns(bad));
});
test('scanDir v1.0-compatible wrapper returns redacted lines',async()=>{
  const root=make();
  try{
    write(root,'test.txt','AKIA'+'P'.repeat(16));
    const lines=await scanDir(root);
    assert.equal(lines.length,1);
    assert.match(lines[0],/aws-access-key in test.txt:1/);
    assert.ok(!lines[0].includes('AKIA'));
  }finally{clean(root);}
});
test('fails on inaccessible/missing root instead of claiming clean',async()=>{
  await assert.rejects(()=>scanDirectory(path.join(os.tmpdir(),'unknown-secret-scanner-root-39001')));
});
