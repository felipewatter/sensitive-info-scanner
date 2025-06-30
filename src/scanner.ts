import fs from 'fs';
import path from 'path';
import { defaultPatterns } from './patterns';

export async function scanDir(dirPath: string): Promise<string[]> {
  const issues: string[] = [];
  const files = fs.readdirSync(dirPath);

  for (const file of files) {
    const fullPath = path.join(dirPath, file);

    if (fs.statSync(fullPath).isDirectory()) {
      if (file === 'node_modules' || file === '.git') continue;
      issues.push(...await scanDir(fullPath));
    } else {
      const content = fs.readFileSync(fullPath, 'utf8');
      for (const pattern of defaultPatterns) {
        if (pattern.regex.test(content) || pattern.regex.test(file)) {
          issues.push(`⚠️ Potential ${pattern.name} in ${fullPath}`);
        }
      }
    }
  }

  return issues;
}