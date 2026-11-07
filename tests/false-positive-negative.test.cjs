const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {scanDirectory} = require('../dist/src/scanner.js');
const {hasSensitiveFilename, validateLiteralPatterns} = require('../dist/src/patterns.js');

const withFixture = async (files, check) => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'sis-boundary-'));
  try {
    for (const [name, value] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(root,name)),{recursive:true});
      fs.writeFileSync(path.join(root,name), value);
    }
    await check(root);
  } finally {fs.rmSync(root,{recursive:true,force:true});}
};

test('known secret formats are detected, near-misses do not trigger', async () => {
  const valid=['AKIA'+'A'.repeat(16),'ghp_'+'B'.repeat(36),
    'github_pat_'+'C'.repeat(28),'AIza'+'D'.repeat(35),
    'sk_live_'+'E'.repeat(20)];
  const invalid=['AKIA'+'A'.repeat(15),'ghp_'+'B'.repeat(35),
    'AIza'+'D'.repeat(34),'api_key = short','password = placeholder'];
  await withFixture({'valid.txt':valid.join('\n'),'benign.txt':invalid.join('\n')},async root=>{
    const result=await scanDirectory(root);
    const rules=new Set(result.findings.map(f=>f.rule));
    for (const rule of ['aws-access-key','github-token','github-fine-grained-token',
      'google-api-key','stripe-secret-key']) assert.ok(rules.has(rule), rule);
    assert.equal(result.findings.filter(f=>f.path==='benign.txt').length,0);
    for (const value of valid)assert.equal(JSON.stringify(result).includes(value),false);
  });
});

test('filenames handle examples, public keys and credential-like files without leaking data', async()=>{
  await withFixture({
    '.env.example':'DEMO=placeholder',
    '.env.template':'DEMO=placeholder',
    'id_ed25519.pub':'public',
    'credentials.json':'do-not-output-content',
    'server.key':Buffer.from([0,1,2,3]),
  },async root=>{
    const result=await scanDirectory(root);
    const found=result.findings.filter(f=>f.rule==='sensitive-filename');
    assert.deepEqual(found.map(f=>f.path).sort(),['credentials.json','server.key']);
    assert.ok(found.every(f=>f.line===null));
    assert.equal(hasSensitiveFilename('.env.template'),false);
    assert.equal(hasSensitiveFilename('id_ed25519.pub'),false);
    assert.ok(!JSON.stringify(result).includes('do-not-output-content'));
  });
});

test('case-sensitive custom literals distinguish intended match only',async()=>{
  const patterns=validateLiteralPatterns({patterns:[{id:'internal-marker',literal:'MARKER',caseSensitive:true}]});
  await withFixture({'data.txt':'marker\nMARKER'},async root=>{
    const found=(await scanDirectory(root,{customPatterns:patterns})).findings;
    assert.deepEqual(found.map(f=>f.line),[2]);
  });
});
