#!/usr/bin/env node
import { scanDir } from '../src/scanner';

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('❌ Please provide a path to scan');
  process.exit(1);
}

(async () => {
  console.log('🔎 Sensitive Info Scanner\n---------------------------------------');
  const issues = await scanDir(args[0]);
  if (issues.length === 0) {
    console.log('✔️ No issues found');
  } else {
    for (const issue of issues) {
      console.log(issue);
    }
    console.log(`---------------------------------------\nSummary: ${issues.length} potential issues found`);
  }
})();