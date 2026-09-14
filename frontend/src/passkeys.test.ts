import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, onAuthenticationExpired, request, setCSRFToken } from './api'
import { creationOptions, credentialJSON, decodeBase64URL, deletePasskey, encodeBase64URL, loginWithPasskey, passkeyError, passkeySupport, registerPasskey, requestOptions } from './passkeys'

const bytes = new Uint8Array([0, 255, 254, 1]).buffer
const creation = { challenge: 'AP_-AQ', rp: { name: 'boxctl', id: 'localhost' }, user: { id: 'AP_-AQ', name: 'Administrator', displayName: 'boxctl Administrator' }, pubKeyCredParams: [{ type: 'public-key' as const, alg: -7 }], authenticatorSelection: { residentKey: 'required' as const, userVerification: 'required' as const }, excludeCredentials: [{ type: 'public-key' as const, id: 'AP_-AQ', transports: ['internal' as const] }] }
const assertionCredential = { id: 'AP_-AQ', rawId: bytes, type: 'public-key', authenticatorAttachment: 'platform', getClientExtensionResults: () => ({}), response: { clientDataJSON: bytes, authenticatorData: bytes, signature: bytes, userHandle: bytes } } as unknown as PublicKeyCredential
const registrationCredential = { ...assertionCredential, response: { clientDataJSON: bytes, attestationObject: bytes, getTransports: () => ['internal'] } } as unknown as PublicKeyCredential
const data = (value: unknown) => new Response(JSON.stringify({ data: value }), { status: 200 })

afterEach(() => { vi.unstubAllGlobals(); setCSRFToken('') })

describe('passkey browser integration', () => {
  it('round trips binary WebAuthn fields and retains authenticator requirements', () => {
    expect(encodeBase64URL(bytes)).toBe('AP_-AQ')
    expect(decodeBase64URL('AP_-AQ')).toEqual(bytes)
    const decoded = creationOptions(creation)
    expect(decoded.challenge).toEqual(bytes)
    expect(decoded.user.id).toEqual(bytes)
    expect(decoded.excludeCredentials?.[0]).toEqual({ type: 'public-key', id: bytes, transports: ['internal'] })
    expect(decoded.authenticatorSelection).toEqual({ residentKey: 'required', userVerification: 'required' })
    expect(requestOptions({ challenge: 'AP_-AQ', userVerification: 'required' }).allowCredentials).toBeUndefined()
    expect(credentialJSON(assertionCredential).response).toMatchObject({ signature: 'AP_-AQ', userHandle: 'AP_-AQ' })
    expect(credentialJSON(registrationCredential).response).toMatchObject({ attestationObject: 'AP_-AQ', transports: ['internal'] })
  })

  it('signs in without any password and installs the session CSRF token', async () => {
    const get = vi.fn(async (_options?: CredentialRequestOptions) => assertionCredential)
    vi.stubGlobal('navigator', { credentials: { get } })
    const fetchMock = vi.fn(async (path: RequestInfo | URL, _init?: RequestInit) => String(path).endsWith('/begin') ? data({ ceremonyId: 'login-once', options: { publicKey: { challenge: 'AP_-AQ', rpId: 'localhost', userVerification: 'required' } } }) : data({ authenticated: true, csrfToken: 'new-csrf' }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(loginWithPasskey()).resolves.toMatchObject({ authenticated: true })
    expect(get.mock.calls[0]?.[0]).toMatchObject({ publicKey: { challenge: bytes, userVerification: 'required' } })
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({})
    expect(JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body))).toMatchObject({ ceremonyId: 'login-once', credential: { type: 'public-key' } })
    expect(String(fetchMock.mock.calls[1]?.[1]?.body)).not.toContain('password')
    await request('/settings', { method: 'PUT', body: '{}' })
    expect(new Headers(fetchMock.mock.calls[2]?.[1]?.headers).get('X-CSRF-Token')).toBe('new-csrf')
  })

  it('confirms the password before calling the authenticator and sends no password on finish', async () => {
    const create = vi.fn(async () => registrationCredential)
    vi.stubGlobal('navigator', { credentials: { create } })
    const fetchMock = vi.fn(async (path: RequestInfo | URL, _init?: RequestInit) => String(path).endsWith('/begin') ? data({ ceremonyId: 'register-once', options: { publicKey: creation } }) : data([]))
    vi.stubGlobal('fetch', fetchMock)
    setCSRFToken('existing-csrf')
    await registerPasskey(' MacBook ', 'current password')
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ name: 'MacBook', password: 'current password' })
    expect(String(fetchMock.mock.calls[1]?.[1]?.body)).not.toContain('password')
    expect(create).toHaveBeenCalledOnce()
    for (const [, init] of fetchMock.mock.calls) expect(new Headers(init?.headers).get('X-CSRF-Token')).toBe('existing-csrf')
  })

  it('keeps the panel session on a wrong confirmation password and never opens the authenticator', async () => {
    const create = vi.fn()
    const expired = vi.fn()
    const unsubscribe = onAuthenticationExpired(expired)
    vi.stubGlobal('navigator', { credentials: { create } })
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'invalid_password', message: 'Incorrect password' } }), { status: 403 })))
    await expect(registerPasskey('MacBook', 'wrong')).rejects.toMatchObject({ status: 403 })
    await expect(deletePasskey('id', 'wrong')).rejects.toMatchObject({ status: 403 })
    expect(create).not.toHaveBeenCalled()
    expect(expired).not.toHaveBeenCalled()
    unsubscribe()
  })

  it('does not finish a canceled browser ceremony', async () => {
    vi.stubGlobal('navigator', { credentials: { get: vi.fn(async () => { throw new DOMException('Canceled', 'NotAllowedError') }) } })
    const fetchMock = vi.fn(async () => data({ ceremonyId: 'cancel-me', options: { publicKey: { challenge: 'AP_-AQ' } } }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(loginWithPasskey()).rejects.toMatchObject({ name: 'NotAllowedError' })
    expect(fetchMock).toHaveBeenCalledOnce()
  })

  it('requires a password for each deletion', async () => {
    const fetchMock = vi.fn(async (_path: RequestInfo | URL, _init?: RequestInit) => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    await deletePasskey('id', 'fresh password')
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('DELETE')
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({ id: 'id', password: 'fresh password' })
  })

  it.each([
    ['http:', 'localhost', true, 'available'], ['https:', 'router.example', true, 'available'],
    ['http:', 'router.example', false, 'insecure'], ['https:', '192.168.1.1', true, 'insecure'], ['http:', '127.0.0.1', true, 'insecure'], ['https:', '[::1]', true, 'insecure'],
  ])('detects support on %s//%s', (protocol, hostname, isSecureContext, expected) => {
    vi.stubGlobal('window', { location: { protocol, hostname }, isSecureContext })
    vi.stubGlobal('PublicKeyCredential', class {})
    vi.stubGlobal('navigator', { credentials: { create: vi.fn(), get: vi.fn() } })
    expect(passkeySupport()).toBe(expected)
  })

  it('provides localized action errors', () => {
    expect(passkeyError(new DOMException('canceled', 'NotAllowedError'), (key) => key)).toBe('passkeyCanceled')
    expect(passkeyError(new APIError(403, 'invalid_password', 'wrong'), (key) => key)).toBe('passkeyInvalidPassword')
    expect(passkeyError(new APIError(500, 'save_failed', 'Could not save'), (key) => key)).toBe('Could not save')
  })
})
