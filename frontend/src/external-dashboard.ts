import { request } from './api'
import type { ExternalDashboardOpen, ExternalDashboardStatus } from './types'

export interface ExternalDashboardClient {
  status(): Promise<ExternalDashboardStatus>
  open(): Promise<ExternalDashboardOpen>
}

export interface ExternalDashboardLaunchResult {
  open: ExternalDashboardOpen
  status: ExternalDashboardStatus
}

export const externalDashboardClient: ExternalDashboardClient = {
  status: () => request<ExternalDashboardStatus>('/external-dashboard'),
  open: () => request<ExternalDashboardOpen>('/external-dashboard/open'),
}

export class ExternalDashboardLauncher {
  private pending?: Promise<ExternalDashboardLaunchResult>

  constructor(private readonly client: ExternalDashboardClient) {}

  get busy(): boolean {
    return this.pending !== undefined
  }

  launch(): Promise<ExternalDashboardLaunchResult> {
    if (this.pending) return this.pending

    const operation = this.prepare()
    this.pending = operation
    const clear = () => {
      if (this.pending === operation) this.pending = undefined
    }
    operation.then(clear, clear)
    return operation
  }

  private async prepare(): Promise<ExternalDashboardLaunchResult> {
    const status = await this.client.status()
    if (!status.installed) throw new Error('external dashboard is not installed')
    const open = await this.client.open()
    return { open, status }
  }
}

export function externalDashboardURL(open: ExternalDashboardOpen, currentLocation: string | URL): string {
  const current = currentLocation instanceof URL ? currentLocation : new URL(currentLocation)
  const destination = new URL(open.path, current.origin)
  const protocol = current.protocol.replace(/:$/, '')
  const parameters = new URLSearchParams({
    protocol,
    hostname: current.hostname,
    port: current.port || (protocol === 'https' ? '443' : '80'),
    secondaryPath: open.controllerPath,
    disableUpgradeCore: '1',
  })
  destination.hash = `/setup?${parameters.toString()}`
  return destination.toString()
}
