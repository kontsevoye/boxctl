import { useEffect, useState } from 'react'
import { APIError, coreDashboardStreamURL } from './api'
import { useAppRefreshSignal } from './app-events'
import type { CoreDashboard, DelaySample, Provider, ProxyGroup, ProxyOption } from './types'

export type DashboardStreamState = 'open' | 'reconnecting'

export function useCoreDashboard() {
  const [dashboard, setDashboard] = useState<CoreDashboard>()
  const [streamState, setStreamState] = useState<DashboardStreamState>('reconnecting')
  const [error, setError] = useState<APIError>()
  const [revision, setRevision] = useState(0)
  const appRevision = useAppRefreshSignal()

  useEffect(() => {
    const source = new EventSource(coreDashboardStreamURL(), { withCredentials: true })
    source.onopen = () => setStreamState('open')
    source.onerror = () => setStreamState('reconnecting')
    source.addEventListener('dashboard', (event) => {
      try {
        setDashboard(parseDashboardEvent((event as MessageEvent<string>).data))
        setError(undefined)
      } catch (reason) {
        setError(new APIError(0, 'invalid_stream_payload', reason instanceof Error ? reason.message : String(reason)))
      }
    })
    return () => source.close()
  }, [appRevision, revision])

  return {
    dashboard,
    error,
    loading: dashboard === undefined,
    streamState,
    reload: () => setRevision((current) => current + 1),
  }
}

export function parseDashboardEvent(data: string): CoreDashboard {
  const parsed: unknown = JSON.parse(data)
  if (!parsed || typeof parsed !== 'object') throw new Error('Invalid dashboard stream payload')
  const dashboard = parsed as Partial<CoreDashboard>
  if (!Array.isArray(dashboard.groups) || typeof dashboard.capturedAt !== 'string') {
    throw new Error('Invalid dashboard stream payload')
  }
  if (dashboard.mode !== undefined && !['rule', 'global', 'direct'].includes(dashboard.mode)) {
    throw new Error('Invalid dashboard routing mode')
  }
  if (!dashboard.groups.every(validProxyGroup)
    || !optionalArray(dashboard.proxyProviders, validProvider)
    || !optionalArray(dashboard.ruleProviders, validProvider)
    || !validTraffic(dashboard.traffic)) {
    throw new Error('Invalid dashboard stream payload')
  }
  return dashboard as CoreDashboard
}

function validProxyGroup(value: unknown): value is ProxyGroup {
  if (!isRecord(value) || typeof value.name !== 'string' || typeof value.type !== 'string') return false
  return optionalString(value.icon)
    && optionalString(value.selected)
    && optionalArray(value.options, validProxyOption)
    && optionalArray(value.history, validDelaySample)
}

function validProxyOption(value: unknown): value is ProxyOption {
  if (!isRecord(value) || typeof value.name !== 'string') return false
  return optionalString(value.type)
    && optionalString(value.icon)
    && optionalBoolean(value.udp)
    && optionalFiniteNumber(value.delayMs)
    && optionalBoolean(value.alive)
    && optionalArray(value.history, validDelaySample)
}

function validDelaySample(value: unknown): value is DelaySample {
  return isRecord(value) && optionalString(value.time) && finiteNumber(value.delayMs)
}

function validProvider(value: unknown): value is Provider {
  if (!isRecord(value) || typeof value.name !== 'string') return false
  for (const key of ['type', 'vehicleType', 'updatedAt', 'behavior', 'format']) {
    if (!optionalString(value[key])) return false
  }
  for (const key of ['proxyCount', 'ruleCount']) {
    if (!optionalFiniteNumber(value[key])) return false
  }
  if (value.subscriptionInfo !== undefined) {
    if (!isRecord(value.subscriptionInfo)) return false
    for (const key of ['uploadBytes', 'downloadBytes', 'totalBytes', 'expireAt']) {
      if (!optionalFiniteNumber(value.subscriptionInfo[key])) return false
    }
  }
  if (value.healthCheck !== undefined) {
    if (!isRecord(value.healthCheck) || typeof value.healthCheck.enabled !== 'boolean'
      || !optionalFiniteNumber(value.healthCheck.interval) || !optionalBoolean(value.healthCheck.lazy)) return false
  }
  return true
}

function validTraffic(value: unknown): boolean {
  return value === undefined || (isRecord(value)
    && finiteNumber(value.uploadRateBytes)
    && finiteNumber(value.downloadRateBytes)
    && optionalString(value.capturedAt))
}

function optionalArray<T>(value: unknown, itemGuard: (item: unknown) => item is T): boolean {
  return value === undefined || (Array.isArray(value) && value.every(itemGuard))
}

function optionalString(value: unknown): boolean {
  return value === undefined || typeof value === 'string'
}

function optionalBoolean(value: unknown): boolean {
  return value === undefined || typeof value === 'boolean'
}

function optionalFiniteNumber(value: unknown): boolean {
  return value === undefined || finiteNumber(value)
}

function finiteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}
