import { spawn } from 'node:child_process'

/**
 * Log a proxy deny to the macOS unified log (on macOS) so that it is captured
 * by srt-log without writing to stderr.
 *
 * Writing to stderr is avoided because the srt host process shares a terminal
 * with the sandboxed child (e.g. Claude Code CLI), and any stderr output
 * interrupts TUI rendering.
 *
 * On macOS the message is written via `logger`, which emits to the unified log.
 * The message is suffixed with `_SBX` so that srt-log's predicate
 * (eventMessage ENDSWITH "_SBX") captures it alongside seatbelt violations.
 *
 * On non-macOS platforms the message falls through to logForDebugging only.
 *
 * Example output in srt-log:
 *   srt proxy-blocked: HTTPS-CONNECT api.example.com:443_SBX
 */
export function logProxyDeny(
  protocol: 'HTTPS-CONNECT' | 'HTTP' | 'SOCKS',
  hostname: string,
  port: number,
): void {
  if (process.platform === 'darwin') {
    // Suffix _SBX matches srt-log predicate: eventMessage ENDSWITH "_SBX"
    const message = `srt proxy-blocked: ${protocol} ${hostname}:${port}_SBX`
    spawn('logger', [message], { detached: true, stdio: 'ignore' }).unref()
  }
  // Also surface in SRT_DEBUG stream for users with verbose logging enabled
  logForDebugging(
    `proxy-blocked: ${protocol} ${hostname}:${port} - not in allowedDomains`,
    { level: 'error' },
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
