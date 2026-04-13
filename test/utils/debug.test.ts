import { describe, test, expect, beforeEach, afterEach, spyOn } from 'bun:test'
import { logProxyDeny, logForDebugging } from '../../src/utils/debug.js'

describe('logProxyDeny', () => {
  let stderrOutput: string[]
  let writeSpy: ReturnType<typeof spyOn>

  beforeEach(() => {
    stderrOutput = []
    writeSpy = spyOn(process.stderr, 'write').mockImplementation(
      (chunk: string | Uint8Array) => {
        stderrOutput.push(typeof chunk === 'string' ? chunk : chunk.toString())
        return true
      },
    )
  })

  afterEach(() => {
    writeSpy.mockRestore()
  })

  test('emits to stderr for HTTPS-CONNECT even without SRT_DEBUG', () => {
    const saved = process.env.SRT_DEBUG
    delete process.env.SRT_DEBUG

    logProxyDeny('HTTPS-CONNECT', 'api.example.com', 443)

    expect(stderrOutput).toHaveLength(1)
    expect(stderrOutput[0]).toBe(
      '[srt] proxy-blocked: HTTPS-CONNECT api.example.com:443 - not in allowedDomains\n',
    )

    if (saved !== undefined) process.env.SRT_DEBUG = saved
  })

  test('emits to stderr for HTTP even without SRT_DEBUG', () => {
    const saved = process.env.SRT_DEBUG
    delete process.env.SRT_DEBUG

    logProxyDeny('HTTP', 'example.com', 80)

    expect(stderrOutput).toHaveLength(1)
    expect(stderrOutput[0]).toBe(
      '[srt] proxy-blocked: HTTP example.com:80 - not in allowedDomains\n',
    )

    if (saved !== undefined) process.env.SRT_DEBUG = saved
  })

  test('emits to stderr for SOCKS even without SRT_DEBUG', () => {
    const saved = process.env.SRT_DEBUG
    delete process.env.SRT_DEBUG

    logProxyDeny('SOCKS', 'internal.corp', 1080)

    expect(stderrOutput).toHaveLength(1)
    expect(stderrOutput[0]).toBe(
      '[srt] proxy-blocked: SOCKS internal.corp:1080 - not in allowedDomains\n',
    )

    if (saved !== undefined) process.env.SRT_DEBUG = saved
  })

  test('emits to stderr even when SRT_DEBUG is set', () => {
    const saved = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'

    logProxyDeny('HTTPS-CONNECT', 'blocked.example.com', 443)

    expect(stderrOutput).toHaveLength(1)
    expect(stderrOutput[0]).toContain('[srt] proxy-blocked:')

    process.env.SRT_DEBUG = saved ?? ''
    if (saved === undefined) delete process.env.SRT_DEBUG
  })
})

describe('logForDebugging', () => {
  test('is silent when SRT_DEBUG is not set', () => {
    const saved = process.env.SRT_DEBUG
    delete process.env.SRT_DEBUG

    const spy = spyOn(console, 'error').mockImplementation(() => {})
    logForDebugging('should not appear', { level: 'error' })
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()

    if (saved !== undefined) process.env.SRT_DEBUG = saved
  })

  test('logs when SRT_DEBUG is set', () => {
    const saved = process.env.SRT_DEBUG
    process.env.SRT_DEBUG = '1'

    const messages: string[] = []
    const spy = spyOn(console, 'error').mockImplementation(
      (...args: unknown[]) => {
        messages.push(String(args[0]))
      },
    )
    logForDebugging('test message', { level: 'error' })
    expect(messages.some(m => m.includes('test message'))).toBe(true)
    spy.mockRestore()

    process.env.SRT_DEBUG = saved ?? ''
    if (saved === undefined) delete process.env.SRT_DEBUG
  })
})
