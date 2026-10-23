const PATTERNS: Array<[RegExp, string]> = [
  // Authorization: Bearer <token>
  [/(\bbearer\s+)[^\s"',;]+/gi, '$1[REDACTED]'],
  // JSON 风格："password": "value"
  [
    /(["'])(password|passwd|secret|token|api[_-]?key|access[_-]?key)\1(\s*:\s*)(["'])[^"'\n]*\4/gi,
    '$1$2$1$3$4[REDACTED]$4',
  ],
  // key=value / key: value 形式
  [
    /\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\b(\s*[:=]\s*)(["']?)[^"'\s;,]+/gi,
    '$1$2$3[REDACTED]',
  ],
  // GITHUB_TOKEN=... / *_SECRET: ...
  [
    /([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY)[A-Za-z0-9_]*["']?\s*[:=]\s*)(["']?)[^"'\s;,]+/gi,
    '$1$2[REDACTED]',
  ],
  // --password=value / --token value
  [
    /(--(?:password|passwd|secret|token|api-key|api_key))(\s*=\s*|\s+)[^\s"',;]+/gi,
    '$1$2[REDACTED]',
  ],
  // HTTP Basic 认证
  [/\b(Basic\s+)[A-Za-z0-9+/=]{4,}/gi, '$1[REDACTED]'],
  // 常见裸 token 前缀
  [
    /\b(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b/g,
    '[REDACTED]',
  ],
  // URL 中的 user:password@host
  [/([a-z][a-z0-9+.-]*:\/\/)[^/\s@]+:[^/\s@]+@/gi, '$1[REDACTED]@'],
]

/** 把常见密钥形态替换为 [REDACTED]，避免审计日志泄漏明文。 */
export function redactSecrets(input: string): string {
  let output = input
  for (const [pattern, replacement] of PATTERNS) {
    output = output.replace(pattern, replacement)
  }
  return output
}

/** 递归脱敏 payload 中的字符串字段。 */
export function redactDeep(value: unknown): unknown {
  if (typeof value === 'string') return redactSecrets(value)
  if (Array.isArray(value)) return value.map(redactDeep)
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    return Object.fromEntries(
      Object.entries(record).map(([key, entry]) => [key, redactDeep(entry)]),
    )
  }
  return value
}
