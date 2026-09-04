import { describe, expect, it, vi } from 'vitest'
import { ExternalDashboardLauncher, externalDashboardURL, type ExternalDashboardClient } from './external-dashboard'

describe('external dashboard launch', () => {
  it('does not install missing third-party files as a side effect of opening', async () => {
    const calls: string[] = []
    const client: ExternalDashboardClient = {
      status: async () => {
        calls.push('status')
        return { name: 'Zashboard', installed: false, updateAvailable: false }
      },
      open: async () => {
        calls.push('open')
        return { path: '/external-ui/', controllerPath: '/external-ui/controller' }
      },
    }

    await expect(new ExternalDashboardLauncher(client).launch()).rejects.toThrow('external dashboard is not installed')
    expect(calls).toEqual(['status'])
  })

  it('coalesces double clicks into one status/open sequence', async () => {
    let releaseStatus: (() => void) | undefined
    const statusGate = new Promise<void>((resolve) => { releaseStatus = resolve })
    const client: ExternalDashboardClient = {
      status: vi.fn(async () => {
        await statusGate
        return { name: 'Zashboard', installed: true, currentVersion: 'v3.23.0', updateAvailable: false }
      }),
      open: vi.fn(async () => ({ path: '/external-ui/', controllerPath: '/external-ui/controller' })),
    }
    const launcher = new ExternalDashboardLauncher(client)

    const first = launcher.launch()
    const second = launcher.launch()
    expect(first).toBe(second)
    expect(launcher.busy).toBe(true)
    releaseStatus?.()
    await first

    expect(client.status).toHaveBeenCalledTimes(1)
    expect(client.open).toHaveBeenCalledTimes(1)
    expect(launcher.busy).toBe(false)
  })

  it('uses an authenticated same-origin controller URL without a secret', () => {
    const url = new URL(externalDashboardURL(
      { path: '/external-ui/', controllerPath: '/external-ui/controller' },
      'https://[2001:db8::10]/settings',
    ))
    const parameters = new URLSearchParams(url.hash.split('?')[1])

    expect(url.origin).toBe('https://[2001:db8::10]')
    expect(parameters.get('protocol')).toBe('https')
    expect(parameters.get('hostname')).toBe('[2001:db8::10]')
    expect(parameters.get('port')).toBe('443')
    expect(parameters.get('secondaryPath')).toBe('/external-ui/controller')
    expect(parameters.get('disableUpgradeCore')).toBe('1')
    expect(parameters.has('secret')).toBe(false)
    expect(url.toString()).not.toContain('secret')
  })
})
