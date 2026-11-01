/** Curated, bounded detection signatures; never include matched secrets in findings. */
export type Severity = 'medium' | 'high' | 'critical';
export type Pattern = {id: string; severity: Severity; regex: RegExp};
export type LiteralPattern = {id: string; literal: string; caseSensitive: boolean};
export const defaultPatterns: Pattern[] = [
  {id: 'aws-access-key', severity: 'high', regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/},
  {id: 'github-token', severity: 'critical', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/},
  {id: 'github-fine-grained-token', severity: 'critical', regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/},
  {id: 'slack-token', severity: 'high', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,160}\b/},
  {id: 'stripe-secret-key', severity: 'critical', regex: /\bsk_(?:live|test)_[A-Za-z0-9]{16,160}\b/},
  {id: 'google-api-key', severity: 'high', regex: /\bAIza[0-9A-Za-z_-]{35}\b/},
  {id: 'private-key-block', severity: 'critical', regex: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/},
  {id: 'generic-secret-assignment', severity: 'medium', regex: /\b(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|password|passwd)\b\s*[:=]\s*['"]?[A-Za-z0-9_+/.=-]{20,160}/i},
];
const sensitiveBasenames = /^(?:\.env(?:\.[A-Za-z0-9_-]+)?|id_(?:rsa|dsa|ecdsa|ed25519)|credentials\.json|service-account(?:\.json)?|[A-Za-z0-9_.-]+\.(?:pem|p12|pfx|key))$/i;
const exemptBasenames = /^(?:\.env\.example|\.env\.sample|\.env\.template|.*\.pub)$/i;
export function hasSensitiveFilename(name: string): boolean {
  return !exemptBasenames.test(name) && sensitiveBasenames.test(name);
}
export function validateLiteralPatterns(value: unknown): LiteralPattern[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Custom pattern file must be a JSON object');
  const patterns = (value as {patterns?: unknown}).patterns;
  if (!Array.isArray(patterns) || patterns.length < 1 || patterns.length > 20) throw Error('Custom patterns must contain 1 to 20 items');
  const ids = new Set<string>();
  return patterns.map((p: unknown) => {
    if (!p || typeof p !== 'object' || Array.isArray(p)) throw Error('Invalid custom pattern');
    const v = p as Record<string,unknown>;
    if (typeof v.id !== 'string' || !/^[a-z][a-z0-9-]{2,39}$/.test(v.id) || ids.has(v.id))
      throw Error('Invalid or duplicate custom pattern id');
    if (typeof v.literal !== 'string' || v.literal.length < 4 || v.literal.length > 128 || /[\r\n\u0000]/.test(v.literal))
      throw Error('Custom literal length must be 4..128 without newlines');
    if (v.caseSensitive !== undefined && typeof v.caseSensitive !== 'boolean')
      throw Error('caseSensitive must be boolean');
    ids.add(v.id);
    return {id: 'custom-' + v.id,literal:v.literal,caseSensitive:v.caseSensitive === true};
  });
}
