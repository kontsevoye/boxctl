import { afterEach, describe, expect, it, vi } from 'vitest'
import { activateProfile, profileActivationPayload } from './profile-activation'

afterEach(() => vi.unstubAllGlobals())

describe('profile activation', () => {
  it('uses one disruptive activation contract from profiles and the editor', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)

    await activateProfile('sing-box:Home/main')

    expect(profileActivationPayload()).toEqual({ confirmRestart: true })
    expect(fetchMock).toHaveBeenCalledOnce()
    const [path, init] = fetchMock.mock.calls[0]!
    expect(path).toBe('/api/v1/profiles/sing-box%3AHome%2Fmain/activate')
    expect(init).toMatchObject({ method: 'POST', body: '{"confirmRestart":true}', credentials: 'same-origin' })
  })
})
