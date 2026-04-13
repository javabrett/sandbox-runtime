/**
 * Log a proxy deny unconditionally to stderr.
 *
 * This is always emitted (no env var gate) so that blocked network connections
 * are visible without needing SRT_DEBUG=1. The output goes to stderr to avoid
 * corrupting any stdout JSON stream the caller may be producing.
 *
 * Format: [srt] proxy-blocked: <PROTOCOL> <hostname>:<port> - not in allowedDomains
 */
export function logProxyDeny(
  protocol: 'HTTPS-CONNECT' | 'HTTP' | 'SOCKS',
  hostname: string,
  port: number,
): void {
  process.stderr.write(
    `[srt] proxy-blocked: ${protocol} ${hostname}:${port} - not in allowedDomains\n`,
  )
}

/**
 * Simple debug logging for standalone sandbox
 */
export function logForDebugging(
  message: string,
  options?: { level?: 'info' | 'error' | 'warn' },
): void {
  // Only log if SRT_DEBUG environment variable is set
  // Using SRT_DEBUG instead of DEBUG to avoid conflicts with other tools
  // (DEBUG is commonly used by Node.js debug libraries and VS Code)
  if (!process.env.SRT_DEBUG) {
    return
  }

  const level = options?.level || 'info'
  const prefix = '[SandboxDebug]'

  // Always use stderr to avoid corrupting stdout JSON streams
  switch (level) {
    case 'error':
      console.error(`${prefix} ${message}`)
      break
    case 'warn':
      console.warn(`${prefix} ${message}`)
      break
    default:
      console.error(`${prefix} ${message}`)
  }
}
