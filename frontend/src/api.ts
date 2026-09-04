import type { AdminSetupStatus, BackupExportOptions, BackupImportResult, Session } from './types'

interface ErrorEnvelope {
  error?: {
    code?: string
    message?: string
    requestId?: string
  }
}

interface DataEnvelope<T> {
  data: T
}

export class APIError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId?: string,
  ) {
    super(message)
    this.name = 'APIError'
  }
}

let csrfToken = ''
const authenticationExpiredListeners = new Set<() => void>()

export function setCSRFToken(value: string): void {
  csrfToken = value
}

export function clearAuthentication(): void {
  csrfToken = ''
}

export function onAuthenticationExpired(listener: () => void): () => void {
  authenticationExpiredListeners.add(listener)
  return () => authenticationExpiredListeners.delete(listener)
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) {
    headers.set('X-CSRF-Token', csrfToken)
  }

  const response = await fetch(`/api/v1${path}`, {
    ...init,
    method,
    headers,
    credentials: 'same-origin',
  })
  if (response.status === 401) notifyAuthenticationExpired()
  if (response.status === 204) {
    return undefined as T
  }

  const payload = (await response.json().catch(() => ({}))) as DataEnvelope<T> & ErrorEnvelope
  if (!response.ok) {
    throw errorFromEnvelope(response.status, payload)
  }
  return payload.data
}

function errorFromEnvelope(status: number, payload: ErrorEnvelope): APIError {
  return new APIError(
    status,
    payload.error?.code ?? 'request_failed',
    payload.error?.message ?? `HTTP ${status}`,
    payload.error?.requestId,
  )
}

function notifyAuthenticationExpired(): void {
  clearAuthentication()
  for (const listener of authenticationExpiredListeners) listener()
}

async function responseError(response: Response): Promise<APIError> {
  const payload = (await response.json().catch(() => ({}))) as ErrorEnvelope
  return errorFromEnvelope(response.status, payload)
}

export async function getSession(): Promise<Session> {
  const session = await request<Session>('/auth/session')
  setCSRFToken(session.csrfToken)
  return session
}

export async function login(password: string): Promise<Session> {
  const session = await request<Session>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ password }),
  })
  setCSRFToken(session.csrfToken)
  return session
}

export async function getAdminSetupStatus(): Promise<AdminSetupStatus> {
  return request<AdminSetupStatus>('/setup')
}

export async function initializeAdmin(password: string): Promise<AdminSetupStatus> {
  return request<AdminSetupStatus>('/setup', {
    method: 'POST',
    body: JSON.stringify({ password }),
  })
}

export async function logout(): Promise<void> {
  await request('/auth/logout', { method: 'POST', body: '{}' })
  clearAuthentication()
}

export function systemLogStreamURL(): string {
  return '/api/v1/logs/system/stream?limit=200'
}

export function coreLogStreamURL(): string {
  return '/api/v1/core/logs/stream?limit=200'
}

export function connectionsStreamURL(): string {
  return '/api/v1/core/connections/stream'
}

export function coreDashboardStreamURL(): string {
  return '/api/v1/core/dashboard/stream'
}

export async function exportBackup(options: BackupExportOptions = {
  includeAdminPassword: false,
  includeProviderCaches: false,
  includeDashboardUI: false,
}): Promise<{ blob: Blob; filename: string }> {
  const query = new URLSearchParams({
    includeAdminPassword: String(options.includeAdminPassword),
    includeProviderCaches: String(options.includeProviderCaches),
    includeDashboardUI: String(options.includeDashboardUI),
  })
  const response = await fetch(`/api/v1/backups/export?${query}`, {
    credentials: 'same-origin',
    headers: { Accept: 'application/octet-stream' },
  })
  if (response.status === 401) notifyAuthenticationExpired()
  if (!response.ok) throw await responseError(response)
  return {
    blob: await response.blob(),
    filename: contentDispositionFilename(response.headers.get('Content-Disposition')) ?? 'boxctl-backup.bin',
  }
}

export async function importBackup(file: File): Promise<BackupImportResult> {
  const headers = new Headers({
    Accept: 'application/json',
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': contentDispositionAttachment(file.name),
  })
  if (csrfToken) headers.set('X-CSRF-Token', csrfToken)
  const response = await fetch('/api/v1/backups/import', {
    method: 'POST',
    body: file,
    credentials: 'same-origin',
    headers,
  })
  if (response.status === 401) notifyAuthenticationExpired()
  const payload = (await response.json().catch(() => ({}))) as DataEnvelope<BackupImportResult> & ErrorEnvelope
  if (!response.ok) throw errorFromEnvelope(response.status, payload)
  clearAuthentication()
  return payload.data
}

export function contentDispositionFilename(value: string | null): string | undefined {
  if (!value) return undefined
  const encoded = /filename\*=UTF-8''([^;]+)/i.exec(value)?.[1]
  if (encoded) {
    try {
      return decodeURIComponent(encoded)
    } catch {
      return undefined
    }
  }
  const quoted = /filename="([^"]+)"/i.exec(value)?.[1]
  if (quoted) return quoted.replace(/\\(["\\])/g, '$1')
  const plain = /filename=([^;\s]+)/i.exec(value)?.[1]
  return plain
}

function contentDispositionAttachment(filename: string): string {
  const encoded = encodeURIComponent(filename).replace(/['()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  )
  return `attachment; filename*=UTF-8''${encoded}`
}
