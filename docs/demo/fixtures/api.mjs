/** Sanitized, deterministic presentation fixtures, shaped like frontend/src/types.ts.
 * These examples are not measurements from a live router. No credentials or real
 * subscription addresses are read by the capture pipeline.
 */
export const capturedAt = "2026-09-08T12:00:00.000Z";
const enabled = (names) =>
  Object.fromEntries(names.split(" ").map((name) => [name, true]));
const mib = 1024 ** 2;
const gib = 1024 ** 3;
export const capabilities = {
  coreName: "mihomo",
  coreVersion: "v1.19.30",
  pages: enabled(
    "status profiles rawConfig proxySubscriptions settings backups proxies connections rules coreLogs systemLogs ruleLists",
  ),
  actions: enabled(
    "startService stopService restartService reloadCore testProxyDelay selectProxy setRoutingMode updateProxyProvider updateRuleProvider closeConnection closeAllConnections createRuleList editRuleList deleteRuleList exportBackup importBackup cleanupFirewall updateCore",
  ),
  features: {
    ...enabled("proxyProviders ruleProviders routingMode externalDashboard"),
    ruleMutation: false,
  },
};
const management = {
  remoteProfiles: true,
  proxySubscriptions: true,
  localRuleLists: true,
  fakeIPCapture: true,
  updates: true,
  externalDashboard: true,
};
export const engines = [
  {
    id: "mihomo",
    displayName: "Mihomo",
    configFormat: "yaml",
    extensions: [".yaml", ".yml"],
    installed: true,
    compatible: true,
    selected: true,
    running: true,
    installSource: "managed",
    version: "v1.19.30",
    supportedCaptureModes: ["tproxy", "hybrid", "tun", "mixed", "mixed2"],
    management,
  },
  {
    id: "sing-box",
    displayName: "sing-box",
    configFormat: "json",
    extensions: [".json"],
    installed: true,
    compatible: true,
    selected: false,
    running: false,
    installSource: "managed",
    version: "1.14.0",
    supportedCaptureModes: ["tproxy", "hybrid", "tun", "mixed", "mixed2"],
    management: {
      ...management,
      proxySubscriptions: false,
      localRuleLists: false,
      fakeIPCapture: false,
    },
  },
];
export const profiles = [
  {
    id: "everyday",
    name: "Everyday network",
    engine: "mihomo",
    sourceKind: "remote",
    hasSource: true,
    sourceEnabled: true,
    active: true,
    nodeCount: 24,
    updateIntervalHours: 12,
    updateIntervalAuto: true,
    updatedAt: "2026-09-08T08:30:00Z",
    lastCheckedAt: "2026-09-08T08:30:00Z",
    nextUpdateAt: "2026-09-08T20:30:00Z",
  },
  {
    id: "work",
    name: "Work & development",
    engine: "mihomo",
    sourceKind: "local",
    hasSource: false,
    sourceEnabled: false,
    active: false,
    nodeCount: 8,
    updatedAt: "2026-09-07T16:20:00Z",
  },
  {
    id: "travel",
    name: "Travel backup",
    engine: "mihomo",
    sourceKind: "remote",
    hasSource: true,
    sourceEnabled: true,
    active: false,
    nodeCount: 12,
    updateIntervalHours: 24,
    updatedAt: "2026-09-07T11:15:00Z",
    nextUpdateAt: "2026-09-08T11:15:00Z",
  },
  {
    id: "sing-home",
    name: "Home · sing-box",
    engine: "sing-box",
    sourceKind: "local",
    hasSource: false,
    sourceEnabled: false,
    active: false,
    nodeCount: 6,
    updatedAt: "2026-09-08T09:40:00Z",
  },
  {
    id: "sing-travel",
    name: "Travel · sing-box",
    engine: "sing-box",
    sourceKind: "remote",
    hasSource: true,
    sourceEnabled: true,
    active: false,
    nodeCount: 4,
    updateIntervalHours: 24,
    updatedAt: "2026-09-07T14:20:00Z",
  },
];
export const status = {
  healthy: true,
  version: "v2026.09.7",
  boxctlUptimeSeconds: 432845,
  coreUptimeSeconds: 172904,
  core: {
    name: "mihomo",
    version: "v1.19.30",
    state: "running",
    since: "2026-09-06T11:58:16Z",
  },
  activeProfile: { id: "everyday", name: "Everyday network", engine: "mihomo" },
  selectedEngine: "mihomo",
  runningEngine: "mihomo",
  runtimeEpoch: 7,
  resources: {
    manager: { memoryBytes: 12.4 * mib, cpuPercent: 0.2 },
    core: { memoryBytes: 86.7 * mib, cpuPercent: 2.4 },
  },
  traffic: {
    uploadBytes: 2.84 * gib,
    downloadBytes: 38.6 * gib,
    connections: 42,
  },
  warnings: [],
  restartRequired: false,
};
export const settings = {
  language: "en",
  theme: "dark",
  logLevel: "info",
  updateChannel: "stable",
  captureMode: "tproxy",
  availableCaptureModes: ["tproxy", "hybrid", "tun", "mixed", "mixed2"],
  startOnBoot: true,
  autoUpdate: false,
  operatingMode: "gateway",
  dnsMode: "upstream",
  interfaceMode: "exclude",
  includedInterfaces: ["br-lan"],
  excludedInterfaces: ["wan", "wan6"],
  autoDetectWAN: true,
  autoDetectLAN: true,
  interceptRouterOutput: true,
  tunStack: "system",
  tunAddress: "172.19.0.1/30",
  tunMTU: 1500,
  rejectQUIC: false,
  reservedNetworks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  bypassSources: ["192.168.10.50"],
  bypassTCPPorts: [22],
  bypassUDPPorts: [123],
  proxyOnlyTCPPorts: [],
  proxyOnlyUDPPorts: [],
  autoFakeIPWhitelist: true,
  autoFakeIPIncludeExternalIPProviders: false,
  useTmpfsRules: true,
  enableHWID: false,
  autoRefreshProxyIPs: true,
  autoRefreshFakeIP: true,
  maintenanceIntervalMinutes: 30,
  interfaces: [
    { name: "br-lan", role: "lan" },
    { name: "br-guest", role: "lan" },
    { name: "wan", role: "wan" },
    { name: "wan6", role: "wan" },
  ],
  interfaceSource: "ubus",
  externalDashboardEnabled: true,
  coreRestartGuard: true,
  coreRestartGuardSupported: true,
};
const nodes = [
  ["🇳🇱 Amsterdam", "VLESS", 34],
  ["🇩🇪 Frankfurt", "Trojan", 42],
  ["🇫🇮 Helsinki", "Shadowsocks", 51],
  ["🇬🇧 London", "Hysteria2", 63],
  ["🇺🇸 New York", "VLESS", 118],
  ["🇯🇵 Tokyo", "TUIC", 184],
].map(([name, type, delayMs]) => ({
  name,
  type,
  delayMs,
  udp: true,
  alive: true,
  history: [42, 38, 36, 34].map((delayMs) => ({ time: capturedAt, delayMs })),
}));
export const dashboard = {
  capturedAt,
  mode: "rule",
  traffic: { downloadRateBytes: 12.8 * mib, uploadRateBytes: 1.6 * mib },
  groups: [
    {
      name: "Auto · fastest route",
      type: "URLTest",
      selected: nodes[0].name,
      options: nodes,
    },
    {
      name: "Streaming",
      type: "Selector",
      selected: nodes[1].name,
      options: nodes.slice(0, 4),
    },
    {
      name: "Global proxy",
      type: "Selector",
      selected: nodes[0].name,
      options: nodes,
    },
    {
      name: "Work & development",
      type: "Selector",
      selected: nodes[3].name,
      options: nodes.slice(1, 5),
    },
    {
      name: "Gaming",
      type: "Fallback",
      selected: nodes[0].name,
      options: nodes.slice(0, 3),
    },
    {
      name: "Final route",
      type: "Selector",
      selected: "DIRECT",
      options: [
        { name: "DIRECT", type: "Direct", alive: true, delayMs: 2 },
        ...nodes.slice(0, 2),
      ],
    },
  ],
  proxyProviders: [
    {
      name: "Global network",
      type: "Proxy",
      vehicleType: "HTTP",
      updatedAt: capturedAt,
      proxyCount: 24,
      subscriptionInfo: {
        uploadBytes: 2.84 * gib,
        downloadBytes: 38.6 * gib,
        totalBytes: 500 * gib,
        expireAt: 1798761600,
      },
      healthCheck: { enabled: true, interval: 300 },
    },
    {
      name: "Travel network",
      type: "Proxy",
      vehicleType: "HTTP",
      updatedAt: capturedAt,
      proxyCount: 12,
      subscriptionInfo: {
        uploadBytes: 0.24 * gib,
        downloadBytes: 4.8 * gib,
        totalBytes: 100 * gib,
        expireAt: 1798761600,
      },
      healthCheck: { enabled: true, interval: 600 },
    },
  ],
  ruleProviders: [
    {
      name: "private-networks",
      type: "Rule",
      vehicleType: "File",
      behavior: "ipcidr",
      format: "text",
      ruleCount: 18,
      updatedAt: capturedAt,
    },
    {
      name: "streaming",
      type: "Rule",
      vehicleType: "HTTP",
      behavior: "domain",
      format: "yaml",
      ruleCount: 1248,
      updatedAt: capturedAt,
    },
    {
      name: "development",
      type: "Rule",
      vehicleType: "File",
      behavior: "classical",
      format: "text",
      ruleCount: 42,
      updatedAt: capturedAt,
    },
  ],
};
export const subscriptions = dashboard.proxyProviders.map((p, i) => ({
  id: `subscription-${i}`,
  engine: "mihomo",
  name: p.name,
  providerName: p.name,
  sourceKind: "remote",
  enabled: true,
  updateIntervalHours: 12,
  updateIntervalAuto: true,
  proxyCount: p.proxyCount,
  ...p.subscriptionInfo,
  expiresAt: "2027-01-01T00:00:00Z",
  updatedAt: capturedAt,
  nextUpdateAt: "2026-09-09T00:00:00Z",
  headerNames: [],
}));
export const rules = [
  ["RuleSet", "private-networks", "DIRECT"],
  ["DomainSuffix", "github.com", "Work & development"],
  ["DomainSuffix", "githubusercontent.com", "Work & development"],
  ["DomainSuffix", "npmjs.org", "Work & development"],
  ["RuleSet", "development", "Work & development"],
  ["RuleSet", "streaming", "Streaming"],
  ["DomainSuffix", "youtube.com", "Streaming"],
  ["DomainSuffix", "netflix.com", "Streaming"],
  ["DomainKeyword", "speedtest", "DIRECT"],
  ["IPCIDR", "192.168.0.0/16", "DIRECT"],
  ["GeoIP", "private", "DIRECT"],
  ["Match", "", "Global proxy"],
].map(([type, payload, action], index) => ({
  index: index + 1,
  type,
  payload,
  action,
}));
const hosts = [
  "github.com",
  "www.youtube.com",
  "registry.npmjs.org",
  "api.github.com",
  "www.netflix.com",
  "openwrt.org",
  "downloads.openwrt.org",
  "developer.mozilla.org",
];
export const connections = {
  capturedAt,
  downloadTotalBytes: 38.6 * gib,
  uploadTotalBytes: 2.84 * gib,
  memoryBytes: 86.7 * mib,
  active: hosts.map((host, i) => ({
    id: `demo-connection-${String(i + 1).padStart(3, "0")}`,
    network: "tcp",
    type: "TProxy",
    source: `192.168.10.${20 + (i % 3)}:${51000 + i}`,
    sourceIP: `192.168.10.${20 + (i % 3)}`,
    sourcePort: String(51000 + i),
    sourceHostname: ["MacBook-Pro", "Living-room-TV", "Workstation"][i % 3],
    destination: `203.0.113.${10 + i}:443`,
    destinationIP: `203.0.113.${10 + i}`,
    destinationPort: "443",
    host,
    rule: i % 3 ? "RuleSet" : "DomainSuffix",
    rulePayload: i % 3 ? "streaming" : "github.com",
    chains: [
      nodes[i % nodes.length].name,
      i % 3 ? "Streaming" : "Work & development",
    ],
    downloadBytes: (164 - i * 15) * mib,
    uploadBytes: (4.2 - i / 3) * mib,
    downloadRateBytes: (5.3 - i * 0.62) * mib,
    uploadRateBytes: (212 - i * 21) * 1024,
    startedAt: "2026-09-08T11:54:20Z",
    dnsMode: "fake-ip",
  })),
  closed: [
    {
      id: "demo-closed-001",
      host: "example.com",
      network: "tcp",
      type: "TProxy",
      chains: ["DIRECT"],
      downloadBytes: 34500,
      uploadBytes: 8200,
      startedAt: "2026-09-08T11:50:00Z",
      closedAt: "2026-09-08T11:52:00Z",
      sourceIP: "192.168.10.20",
    },
  ],
};
export const ruleLists = [
  {
    id: "development",
    name: "development",
    content:
      "DOMAIN-SUFFIX,github.com\nDOMAIN-SUFFIX,githubusercontent.com\nDOMAIN-SUFFIX,npmjs.org\nDOMAIN-SUFFIX,jsdelivr.net\nDOMAIN-SUFFIX,docker.com\nDOMAIN-SUFFIX,stackoverflow.com\n",
    ruleCount: 6,
  },
  {
    id: "private-networks",
    name: "private-networks",
    content:
      "IP-CIDR,10.0.0.0/8\nIP-CIDR,172.16.0.0/12\nIP-CIDR,192.168.0.0/16\n",
    ruleCount: 3,
  },
  {
    id: "streaming",
    name: "streaming",
    content: "DOMAIN-SUFFIX,youtube.com\nDOMAIN-SUFFIX,netflix.com\n",
    ruleCount: 2,
  },
].map((list) => ({
  ...list,
  engine: "mihomo",
  format: "text",
  enabled: true,
  revision: "demo-rev-01",
  updatedAt: capturedAt,
  providerName: list.name,
  inConfig: true,
  configNameTaken: false,
  inUse: true,
}));
export const fakeIPWhitelist = {
  engine: "mihomo",
  manualContent: "198.18.0.0/16\n",
  generatedCIDRs: ["198.18.0.0/16"],
  fakeIPRanges: ["198.18.0.0/16"],
  effectiveCIDRs: ["198.18.0.0/16"],
  manualCount: 1,
  generatedCount: 1,
  effectiveCount: 1,
  revision: "demo-rev-01",
  generatedAt: capturedAt,
  applicable: true,
  selective: true,
  applied: true,
  restartRequired: false,
  warnings: [],
};
export const logs = {
  core: [
    "[TCP] 192.168.10.20:51000 --> github.com:443 match DomainSuffix(github.com) using Work & development[🇬🇧 London]",
    "[TCP] 192.168.10.21:51001 --> www.youtube.com:443 match RuleSet(streaming) using Streaming[🇩🇪 Frankfurt]",
    "Health check completed: Global network · 24 proxies available",
    "[DNS] resolve registry.npmjs.org from cache: 198.18.0.24",
    "[TCP] 192.168.10.22:51002 --> registry.npmjs.org:443 match RuleSet(development) using Work & development[🇬🇧 London]",
    "Configuration reloaded successfully",
    "Rule provider streaming updated: 1248 rules",
    "[TCP] 192.168.10.20:51003 --> api.github.com:443 match DomainSuffix(github.com) using Work & development[🇬🇧 London]",
  ],
  system: [
    "boxctl manager started",
    "Selected engine: mihomo · v1.19.30",
    "Active profile validated: Everyday network",
    "Capture plan applied: tproxy · br-lan, br-guest",
    "DNS mode configured: upstream",
    "Controller health check passed",
    "Periodic maintenance completed",
    "Proxy subscriptions refreshed successfully",
  ],
};
export const managerUpdate = {
  currentVersion: "v2026.09.7",
  latestVersion: "v2026.09.7",
  updateAvailable: false,
  checkedAt: capturedAt,
  releaseUrl: "https://github.com/kontsevoye/boxctl/releases",
};
export const externalDashboard = {
  name: "Zashboard",
  enabled: true,
  installed: true,
  currentVersion: "v2.7.0",
  latestVersion: "v2.7.0",
  updateAvailable: false,
};
export const configYaml = `# Everyday network · native Mihomo configuration
mixed-port: 7890
mode: rule
log-level: info
allow-lan: true
ipv6: false

dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://dns.cloudflare.com/dns-query
    - https://dns.google/dns-query

proxy-providers:
  global-network:
    type: file
    path: ./providers/global-network.yaml
    health-check:
      enable: true
      interval: 300
      url: https://www.gstatic.com/generate_204

proxy-groups:
  - name: Global proxy
    type: select
    use: [global-network]

rules:
  - RULE-SET,private-networks,DIRECT
  - RULE-SET,development,Global proxy
  - MATCH,Global proxy
`;
export const configJson =
  JSON.stringify(
    {
      log: { level: "info", timestamp: true },
      dns: {
        servers: [{ type: "https", tag: "secure-dns", server: "1.1.1.1" }],
      },
      inbounds: [
        {
          type: "tun",
          tag: "tun-in",
          address: ["172.19.0.1/30"],
          auto_route: true,
          strict_route: true,
        },
      ],
      outbounds: [
        { type: "selector", tag: "Global proxy", outbounds: ["direct"] },
        { type: "direct", tag: "direct" },
      ],
      route: { auto_detect_interface: true, final: "Global proxy" },
      experimental: { clash_api: { external_controller: "127.0.0.1:9090" } },
    },
    null,
    2,
  ) + "\n";
