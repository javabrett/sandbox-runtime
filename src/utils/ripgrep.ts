import { execFile, spawn } from 'child_process'
import type { ExecFileException } from 'child_process'
import { whichSync } from './which.js'

export interface RipgrepConfig {
  command: string
  args?: string[]
  /** Override argv[0] when spawning (for multicall binaries that dispatch on argv[0]) */
  argv0?: string
}

/**
 * Check if ripgrep (rg) is available synchronously
 * Returns true if rg is installed, false otherwise
 */
export function hasRipgrepSync(): boolean {
  return whichSync('rg') !== null
}

/**
 * Execute ripgrep with the given arguments
 * @param args Command-line arguments to pass to rg
 * @param target Target directory or file to search
 * @param abortSignal AbortSignal to cancel the operation
 * @param config Ripgrep configuration (command and optional args)
 * @returns Array of matching lines (one per line of output)
 * @throws Error if ripgrep exits with non-zero status (except exit code 1 which means no matches)
 */
export async function ripGrep(
  args: string[],
  target: string,
  abortSignal: AbortSignal,
  config: RipgrepConfig = { command: 'rg' },
): Promise<string[]> {
  const { command, args: commandArgs = [], argv0 } = config
  const fullArgs = [...commandArgs, ...args, target]

  function finish(
    resolve: (v: string[]) => void,
    reject: (e: Error) => void,
    code: number | null,
    stdout: string,
    stderr: string,
  ): void {
    if (code === 0) {
      resolve(stdout.trim().split('\n').filter(Boolean))
    } else if (code === 1) {
      // Exit code 1 means "no matches found" - this is normal, return empty array
      resolve([])
    } else {
      reject(new Error(`ripgrep failed with exit code ${code}: ${stderr}`))
    }
  }

  // execFile doesn't support argv0; use spawn when argv0 is set
  if (argv0) {
    return new Promise((resolve, reject) => {
      const child = spawn(command, fullArgs, {
        argv0,
        signal: abortSignal,
        windowsHide: true,
      })
      let stdout = ''
      let stderr = ''
      child.stdout?.on('data', d => (stdout += d))
      child.stderr?.on('data', d => (stderr += d))
      const timer = setTimeout(() => child.kill(), 10_000)
      child.on('error', err => {
        clearTimeout(timer)
        reject(err)
      })
      child.on('close', code => {
        clearTimeout(timer)
        finish(resolve, reject, code, stdout, stderr)
      })
    })
  }

  return new Promise((resolve, reject) => {
    execFile(
      command,
      fullArgs,
      {
        maxBuffer: 20_000_000, // 20MB
        signal: abortSignal,
        timeout: 10_000, // 10 second timeout
      },
      (error: ExecFileException | null, stdout: string, stderr: string) => {
        if (!error) {
          finish(resolve, reject, 0, stdout, stderr)
          return
        }
        finish(
          resolve,
          reject,
          typeof error.code === 'number' ? error.code : -1,
          stdout,
          stderr || error.message,
        )
      },
    )
  })
}
