export interface User {
  id: string
  displayName?: string
}

export interface Session {
  authenticated: true
  user: User
  csrfToken: string
  expiresAt: string
}

export interface AdminSetupStatus {
  required: boolean
}

export interface CoreHealth {
  name: string
  version?: string
  state: string
  since?: string
  lastError?: string
}

export type EngineID = 'mihomo' | 'sing-box'

export interface EngineManagement {
  remoteProfiles: boolean
  proxySubscriptions: boolean
  localRuleLists: boolean
  fakeIPCapture: boolean
  updates: boolean
  externalDashboard: boolean
}

export interface EngineInfo {
  id: EngineID
  displayName: string
  configFormat: 'yaml' | 'json'
  extensions: string[]
  installed: boolean
  installSource?: string
  version?: string
  compatible: boolean
  selected: boolean
  running: boolean
  supportedCaptureModes: string[]
  management: EngineManagement
}

export interface ProcessStats {
  memoryBytes: number
  cpuPercent?: number
}

export interface StatusSnapshot {
  healthy: boolean
  version?: string
  boxctlUptimeSeconds?: number
  coreUptimeSeconds?: number
  core: CoreHealth
  activeProfile?: { id: string; name: string; engine?: EngineID }
  selectedEngine?: EngineID
  runningEngine?: EngineID
  runtimeEpoch?: number
  restartRequired?: boolean
  pendingChanges?: string[]
  transition?: string
  traffic?: { uploadBytes: number; downloadBytes: number; connections: number }
  resources?: {
    manager?: ProcessStats
    core?: ProcessStats
  }
  warnings?: Array<{ code: string; message: string; level?: string }>
}

export interface Capabilities {
  coreName: string
  coreVersion?: string
  pages: Record<string, boolean>
  actions: Record<string, boolean>
  features?: Record<string, boolean>
}

export interface Settings {
  language: string
  theme: string
  logLevel: string
  updateChannel: string
  captureMode: string
  availableCaptureModes?: string[]
  startOnBoot: boolean
  autoUpdate: boolean
	operatingMode?: 'gateway' | 'server'
  dnsMode?: 'upstream' | 'redirect' | 'disabled'
  interfaceMode?: 'explicit' | 'exclude'
  includedInterfaces?: string[]
  excludedInterfaces?: string[]
  autoDetectWAN?: boolean
  autoDetectLAN?: boolean
  interceptRouterOutput?: boolean
  tunStack?: string
  tunAddress?: string
  tunMTU?: number
  rejectQUIC?: boolean
  reservedNetworks?: string[]
  bypassSources?: string[]
  bypassTCPPorts?: number[]
  bypassUDPPorts?: number[]
  proxyOnlyTCPPorts?: number[]
  proxyOnlyUDPPorts?: number[]
  autoFakeIPWhitelist?: boolean
  autoFakeIPIncludeExternalIPProviders?: boolean
  useTmpfsRules?: boolean
  enableHWID?: boolean
  autoRefreshProxyIPs?: boolean
  autoRefreshFakeIP?: boolean
  maintenanceIntervalMinutes?: number
	interfaces?: Array<{ name: string; role: 'wan' | 'lan' | 'other' }>
	interfaceSource?: string
}

export interface CoreUpdateStatus {
  engine?: EngineID
  currentVersion?: string
  latestVersion?: string
  channel: string
  updateAvailable: boolean
}

export interface CoreUpdateResult {
  engine?: EngineID
  previousVersion?: string
  currentVersion: string
  restarted: boolean
}

export interface ExternalDashboardStatus {
  name: string
  installed: boolean
  currentVersion?: string
  latestVersion?: string
  updateAvailable: boolean
  updateCheckFailed?: boolean
}

export interface ExternalDashboardResult extends ExternalDashboardStatus {
  changed: boolean
}

export interface ExternalDashboardOpen {
  path: string
  controllerPath: string
}

export interface RuleList {
  id: string
  engine?: EngineID
  name: string
  format: string
  enabled: boolean
  ruleCount?: number
  revision: string
  updatedAt?: string
	providerName?: string
	inConfig: boolean
	configNameTaken: boolean
	inUse: boolean
}

export interface RuleListDocument extends RuleList {
  content: string
}

export interface FakeIPWhitelist {
  engine?: EngineID
  manualContent: string
  generatedCIDRs: string[]
  fakeIPRanges: string[]
  effectiveCIDRs: string[]
  manualCount: number
  generatedCount: number
  effectiveCount: number
  revision: string
  generatedAt?: string
  applicable: boolean
  selective: boolean
  applied: boolean
  restartRequired: boolean
  warnings: string[]
}

export interface BackupImportResult {
  imported: boolean
  restartRequired: boolean
  coreRestarted: boolean
  sessionsRevoked: boolean
  warnings?: string[]
}

export interface BackupExportOptions {
  includeAdminPassword: boolean
  includeProviderCaches: boolean
  includeDashboardUI: boolean
}

export interface Profile {
  id: string
  name: string
  engine: EngineID
  sourceKind: string
  hasSource: boolean
  sourceEnabled: boolean
  active: boolean
  nodeCount?: number
  updateIntervalHours?: number
  updateIntervalAuto?: boolean
  updatedAt?: string
  lastCheckedAt?: string
  nextUpdateAt?: string
  lastError?: string
  fingerprint?: string
  pendingRevision?: string
  appliedRevision?: string
  pendingAt?: string
  restartRequired?: boolean
}

export interface ProxySubscription {
  id: string
  engine?: EngineID
  name: string
  providerName: string
  sourceKind: 'remote' | 'share-links'
  enabled: boolean
  headerNames?: string[]
  updateIntervalHours: number
  updateIntervalAuto?: boolean
  proxyCount?: number
  uploadBytes?: number
  downloadBytes?: number
  totalBytes?: number
  expiresAt?: string
  updatedAt?: string
  lastCheckedAt?: string
  nextUpdateAt?: string
  lastError?: string
}

export interface ProxyOption {
  name: string
  type?: string
  icon?: string
  udp?: boolean
  delayMs?: number
  alive?: boolean
  history?: DelaySample[]
}

export interface DelaySample {
  time?: string
  delayMs: number
}

export interface ProxyGroup {
  name: string
  type: string
  icon?: string
  selected?: string
  options?: ProxyOption[]
  history?: DelaySample[]
}

export interface ProxyDelayResult {
  proxy: string
  delayMs: number
}

export interface Provider {
  name: string
  type?: string
  vehicleType?: string
  updatedAt?: string
  proxyCount?: number
  ruleCount?: number
  behavior?: string
  format?: string
  subscriptionInfo?: {
    uploadBytes?: number
    downloadBytes?: number
    totalBytes?: number
    expireAt?: number
  }
  healthCheck?: {
    enabled: boolean
    interval?: number
    lazy?: boolean
  }
}

export interface CoreDashboard {
  mode?: 'rule' | 'global' | 'direct'
  groups: ProxyGroup[]
  proxyProviders?: Provider[]
  ruleProviders?: Provider[]
  traffic?: {
    uploadRateBytes: number
    downloadRateBytes: number
    capturedAt?: string
  }
  capturedAt: string
}

export interface Connection {
  id: string
  network?: string
  type?: string
  source?: string
  destination?: string
  host?: string
  rule?: string
  rulePayload?: string
  chains?: string[]
  outbound?: string
  uploadBytes?: number
  downloadBytes?: number
  uploadRateBytes?: number
  downloadRateBytes?: number
  startedAt?: string
  closedAt?: string
  dnsMode?: string
  sourceIP?: string
  sourcePort?: string
  destinationIP?: string
  destinationPort?: string
}

export interface ConnectionStreamSnapshot {
  active: Connection[]
  closed?: Connection[]
  downloadTotalBytes: number
  uploadTotalBytes: number
  memoryBytes?: number
  capturedAt: string
}

export interface Rule {
  index: number
  type: string
  payload?: string
  action: string
  size?: number
}

export interface LogEntry {
  time: string
  level: string
  component?: string
  message: string
  fields?: Record<string, unknown>
}
