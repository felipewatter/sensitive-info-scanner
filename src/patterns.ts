export const defaultPatterns: { name: string; regex: RegExp }[] = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'Private Key', regex: /-----BEGIN PRIVATE KEY-----/ },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/ },
  { name: '.env file', regex: /\.env/ },
  { name: 'Generic API Key', regex: /api[_-]?key['"]?\s*[:=]\s*['"][0-9a-zA-Z]{16,}/i },
];