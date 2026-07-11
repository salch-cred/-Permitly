const RULES = [
  { id: 'ignore_instructions', weight: 45, pattern: /ignore\s+(all\s+)?(previous|prior|system)\s+instructions?/i, label: 'Instruction override attempt' },
  { id: 'secret_exfiltration', weight: 55, pattern: /(reveal|print|send|expose|dump).{0,30}(api\s*key|private\s*key|password|secret|token|credential)/i, label: 'Credential exfiltration attempt' },
  { id: 'system_prompt', weight: 35, pattern: /(system\s+prompt|developer\s+message|hidden\s+instructions)/i, label: 'Hidden prompt access attempt' },
  { id: 'privilege_escalation', weight: 50, pattern: /(disable|bypass|override|remove).{0,25}(guardrail|policy|approval|permission|security)/i, label: 'Policy bypass attempt' },
  { id: 'data_exfiltration', weight: 45, pattern: /(upload|post|send).{0,30}(database|customer\s+data|source\s+code|environment\s+variables)/i, label: 'Sensitive data transfer attempt' },
  { id: 'shell_injection', weight: 40, pattern: /(;|&&|\|\|)\s*(curl|wget|bash|sh|nc)\b/i, label: 'Shell injection pattern' },
  { id: 'encoded_payload', weight: 20, pattern: /(base64|atob\(|fromcharcode|data:text\/html)/i, label: 'Encoded payload pattern' }
];

function flatten(value, seen = new Set()) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value !== 'object' || seen.has(value)) return '';
  seen.add(value);
  if (Array.isArray(value)) return value.map(v => flatten(v, seen)).join(' ');
  return Object.entries(value).map(([k,v]) => `${k} ${flatten(v, seen)}`).join(' ');
}

export function scanForPromptInjection(input) {
  const text = flatten(input).slice(0, 100_000);
  const matches = RULES.filter(rule => rule.pattern.test(text)).map(({ id, weight, label }) => ({ id, weight, label }));
  const score = Math.min(100, matches.reduce((sum, m) => sum + m.weight, 0));
  const level = score >= 70 ? 'critical' : score >= 45 ? 'high' : score >= 20 ? 'medium' : 'low';
  return {
    safe: score < 45,
    score,
    level,
    matches,
    recommendation: score >= 70 ? 'block' : score >= 45 ? 'escalate' : score >= 20 ? 'review' : 'allow'
  };
}

export function firewallRules() {
  return RULES.map(({ id, weight, label }) => ({ id, weight, label }));
}
