import { afterEach, describe, expect, it, vi } from 'vitest'
import { contentDispositionFilename, exportBackup, importBackup, login, onAuthenticationExpired, request, setCSRFToken } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
  setCSRFToken('')
})

describe('API client', () => {
  it('logs in with a password-only payload', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({
      data: { user: { id: 'administrator' }, csrfToken: 'csrf' },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await login('correct horse')

    const [, init] = fetchMock.mock.calls[0] ?? []
    expect(JSON.parse(String(init?.body))).toEqual({ password: 'correct horse' })
  })

  it('adds CSRF only to mutating same-origin requests', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => new Response(JSON.stringify({ data: { ok: true } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)
    setCSRFToken('csrf-value')

    await request('/status')
    await request('/service/restart', { method: 'POST' })

    const getHeaders = new Headers(fetchMock.mock.calls[0]?.[1]?.headers)
    const postHeaders = new Headers(fetchMock.mock.calls[1]?.[1]?.headers)
    expect(getHeaders.has('X-CSRF-Token')).toBe(false)
    expect(postHeaders.get('X-CSRF-Token')).toBe('csrf-value')
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/api/v1/service/restart')
  })

  it('does not expose structured internals beyond the safe error envelope', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      error: { code: 'conflict', message: 'Revision changed', requestId: 'req-1' },
    }), { status: 409, headers: { 'Content-Type': 'application/json' } })))

    await expect(request('/config')).rejects.toMatchObject({
      status: 409,
      code: 'conflict',
      message: 'Revision changed',
      requestId: 'req-1',
    })
  })

  it('notifies the application when an established API session expires', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      error: { code: 'unauthorized', message: 'Authentication required' },
    }), { status: 401, headers: { 'Content-Type': 'application/json' } })))
    const expired = vi.fn()
    const unsubscribe = onAuthenticationExpired(expired)

    await expect(request('/status')).rejects.toMatchObject({ status: 401 })

    expect(expired).toHaveBeenCalledOnce()
    unsubscribe()
  })

  it('parses safe download filenames from Content-Disposition', () => {
    expect(contentDispositionFilename('attachment; filename="router-backup.bin"')).toBe('router-backup.bin')
    expect(contentDispositionFilename("attachment; filename*=UTF-8''router%20backup.tgz")).toBe('router backup.tgz')
    expect(contentDispositionFilename(null)).toBeUndefined()
  })

  it('downloads a binary backup without treating it as JSON', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(new Uint8Array([1, 2, 3]), {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': 'attachment; filename="router.bin"',
      },
    }))
    vi.stubGlobal('fetch', fetchMock)

    const result = await exportBackup()

    expect(result.filename).toBe('router.bin')
    expect(Array.from(new Uint8Array(await result.blob.arrayBuffer()))).toEqual([1, 2, 3])
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/backups/export?includeAdminPassword=false&includeProviderCaches=false&includeDashboardUI=false')
    expect(fetchMock.mock.calls[0]?.[1]?.credentials).toBe('same-origin')
  })

  it('uploads raw backup bytes with CSRF and an RFC 5987 filename', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({
      data: { imported: true, restartRequired: true },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    setCSRFToken('backup-csrf')
    const file = new File([new Uint8Array([4, 5, 6])], 'daily router.bin', { type: 'application/octet-stream' })

    const result = await importBackup(file)

    expect(result).toEqual({ imported: true, restartRequired: true })
    const [, init] = fetchMock.mock.calls[0] ?? []
    const headers = new Headers(init?.headers)
    expect(init?.method).toBe('POST')
    expect(init?.body).toBe(file)
    expect(headers.get('Content-Type')).toBe('application/octet-stream')
    expect(headers.get('Content-Disposition')).toBe("attachment; filename*=UTF-8''daily%20router.bin")
    expect(headers.get('X-CSRF-Token')).toBe('backup-csrf')
  })
})
