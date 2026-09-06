// Package web provides the authenticated HTTP API and the embedded management UI.
//
// It deliberately depends on service interfaces and neutral DTOs only. Core-specific
// adapters (Mihomo, sing-box, or future engines) belong outside this package.
package web

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var (
	// ErrNotFound may be returned by an injected service when an object does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict may be returned when the requested state conflicts with current state.
	ErrConflict = errors.New("conflict")
	// ErrUnavailable may be returned when a backing service is temporarily unavailable.
	ErrUnavailable = errors.New("unavailable")
)

// PublicError lets service implementations return a safe error to an API client.
// Internal errors must not be wrapped in PublicError because Message is serialized.
type PublicError struct {
	Status  int
	Code    string
	Message string
}

func (e *PublicError) Error() string { return e.Code + ": " + e.Message }

// Credential contains an authentication record. PasswordRecord is never
// serialized by this package; accepted formats are documented by
// VerifyPBKDF2Record.
type Credential struct {
	UserID         string
	DisplayName    string
	PasswordRecord string
}

// CredentialService returns the single administrator password record.
type CredentialService interface {
	Credential(ctx context.Context) (Credential, error)
}

// AdminSetupStatus is intentionally public and secret-free: it lets a fresh
// installation render the one-time password bootstrap before authentication.
type AdminSetupStatus struct {
	Required bool `json:"required"`
}

// AdminSetupService owns the canonical administrator password bootstrap.
// InitializeAdmin must be atomic across processes and must never replace an
// existing canonical password.
type AdminSetupService interface {
	AdminSetupStatus(ctx context.Context) (AdminSetupStatus, error)
	InitializeAdmin(ctx context.Context, password string) error
}

// SessionSecret is key material persisted outside the web server. RetireAt is set
// when a key is rotated and keeps already-issued sessions valid for their lifetime.
type SessionSecret struct {
	ID        string
	Key       []byte
	CreatedAt time.Time
	RetireAt  time.Time
}

// SessionSecretSet contains one signing key and any still-valid former keys.
type SessionSecretSet struct {
	Current  SessionSecret
	Previous []SessionSecret
}

// SessionSecretStore makes session signing keys survive process restarts. Store
// implementations must protect these values as secrets and persist Save atomically.
type SessionSecretStore interface {
	LoadSessionSecrets(ctx context.Context) (SessionSecretSet, error)
	SaveSessionSecrets(ctx context.Context, secrets SessionSecretSet) error
}

// CoreHealth is a secret-free summary of the selected core.
type CoreHealth struct {
	Name      string    `json:"name"`
	Version   string    `json:"version,omitempty"`
	State     string    `json:"state"`
	Since     time.Time `json:"since,omitempty"`
	LastError string    `json:"lastError,omitempty"`
}

// StatusSnapshot is the dashboard status model.
type StatusSnapshot struct {
	Healthy             bool                 `json:"healthy"`
	Version             string               `json:"version,omitempty"`
	BoxctlUptimeSeconds int64                `json:"boxctlUptimeSeconds,omitempty"`
	CoreUptimeSeconds   int64                `json:"coreUptimeSeconds,omitempty"`
	Core                CoreHealth           `json:"core"`
	ActiveProfile       *ProfileRef          `json:"activeProfile,omitempty"`
	SelectedEngine      string               `json:"selectedEngine,omitempty"`
	RunningEngine       string               `json:"runningEngine,omitempty"`
	RuntimeEpoch        uint64               `json:"runtimeEpoch,omitempty"`
	RestartRequired     bool                 `json:"restartRequired,omitempty"`
	PendingChanges      []string             `json:"pendingChanges,omitempty"`
	Transition          string               `json:"transition,omitempty"`
	Traffic             *TrafficStats        `json:"traffic,omitempty"`
	Resources           *ResourceStats       `json:"resources,omitempty"`
	Warnings            []Notice             `json:"warnings,omitempty"`
	RestartGuard        *RestartGuardStatus  `json:"restartGuard,omitempty"`
	ManagerUpdate       *ManagerUpdateStatus `json:"managerUpdate,omitempty"`
}

// RestartGuardStatus describes the temporary LAN forwarding block separately
// from core health, so a cleanup error never stops a healthy core.
type RestartGuardStatus struct {
	Active              bool       `json:"active"`
	Reason              string     `json:"reason,omitempty"`
	ExpiresAt           *time.Time `json:"expiresAt,omitempty"`
	ProtectedInterfaces []string   `json:"protectedInterfaces,omitempty"`
	TrustedInterfaces   []string   `json:"trustedInterfaces,omitempty"`
	LastError           string     `json:"lastError,omitempty"`
}

// ManagerUpdateStatus is populated asynchronously and never makes /status
// depend on GitHub availability.
type ManagerUpdateStatus struct {
	CurrentVersion  string     `json:"currentVersion,omitempty"`
	LatestVersion   string     `json:"latestVersion,omitempty"`
	UpdateAvailable bool       `json:"updateAvailable"`
	ReleaseURL      string     `json:"releaseUrl,omitempty"`
	CheckedAt       *time.Time `json:"checkedAt,omitempty"`
	CheckFailed     bool       `json:"checkFailed,omitempty"`
}

type ProfileRef struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Engine string `json:"engine"`
}

// EngineInfo describes one selectable native core without exposing local
// paths, controller credentials, or release URLs. Runtime capabilities remain
// available from /core/capabilities; Management describes boxctl-owned
// resources which can also be edited while this engine is not running.
type EngineInfo struct {
	ID                    string                       `json:"id"`
	DisplayName           string                       `json:"displayName"`
	ConfigFormat          string                       `json:"configFormat"`
	Extensions            []string                     `json:"extensions"`
	Installed             bool                         `json:"installed"`
	InstallSource         string                       `json:"installSource,omitempty"`
	Version               string                       `json:"version,omitempty"`
	Compatible            bool                         `json:"compatible"`
	Selected              bool                         `json:"selected"`
	Running               bool                         `json:"running"`
	SupportedCaptureModes []string                     `json:"supportedCaptureModes"`
	Management            EngineManagementCapabilities `json:"management"`
}

type EngineManagementCapabilities struct {
	RemoteProfiles     bool `json:"remoteProfiles"`
	ProxySubscriptions bool `json:"proxySubscriptions"`
	LocalRuleLists     bool `json:"localRuleLists"`
	FakeIPCapture      bool `json:"fakeIPCapture"`
	Updates            bool `json:"updates"`
	ExternalDashboard  bool `json:"externalDashboard"`
}

type EngineService interface {
	Engines(ctx context.Context) ([]EngineInfo, error)
}

type TrafficStats struct {
	UploadBytes   int64 `json:"uploadBytes"`
	DownloadBytes int64 `json:"downloadBytes"`
	Connections   int   `json:"connections"`
}

type ProcessStats struct {
	MemoryBytes uint64   `json:"memoryBytes"`
	CPUPercent  *float64 `json:"cpuPercent,omitempty"`
}

type ResourceStats struct {
	Manager *ProcessStats `json:"manager,omitempty"`
	Core    *ProcessStats `json:"core,omitempty"`
}

type Notice struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Level   string `json:"level,omitempty"`
}

type StatusService interface {
	Status(ctx context.Context) (StatusSnapshot, error)
}

// Settings is intentionally a public allow-list. Credentials, API secrets,
// subscription URLs, and engine configuration must not be added to this DTO.
type Settings struct {
	CoreRestartGuard                     bool              `json:"coreRestartGuard"`
	CoreRestartGuardSupported            bool              `json:"coreRestartGuardSupported"`
	Language                             string            `json:"language"`
	Theme                                string            `json:"theme"`
	LogLevel                             string            `json:"logLevel"`
	UpdateChannel                        string            `json:"updateChannel"`
	CaptureMode                          string            `json:"captureMode"`
	AvailableCaptureModes                []string          `json:"availableCaptureModes,omitempty"`
	StartOnBoot                          bool              `json:"startOnBoot"`
	AutoUpdate                           bool              `json:"autoUpdate"`
	OperatingMode                        string            `json:"operatingMode"`
	DNSMode                              string            `json:"dnsMode,omitempty"`
	InterfaceMode                        string            `json:"interfaceMode,omitempty"`
	AutoDetectWAN                        bool              `json:"autoDetectWAN"`
	AutoDetectLAN                        bool              `json:"autoDetectLAN"`
	InterceptRouterOutput                bool              `json:"interceptRouterOutput"`
	IncludedInterfaces                   []string          `json:"includedInterfaces,omitempty"`
	ExcludedInterfaces                   []string          `json:"excludedInterfaces,omitempty"`
	TUNStack                             string            `json:"tunStack,omitempty"`
	TUNAddress                           string            `json:"tunAddress,omitempty"`
	TUNMTU                               uint32            `json:"tunMTU,omitempty"`
	RejectQUIC                           bool              `json:"rejectQUIC,omitempty"`
	ReservedNetworks                     []string          `json:"reservedNetworks,omitempty"`
	BypassSources                        []string          `json:"bypassSources,omitempty"`
	BypassTCPPorts                       []uint16          `json:"bypassTCPPorts,omitempty"`
	BypassUDPPorts                       []uint16          `json:"bypassUDPPorts,omitempty"`
	ProxyOnlyTCPPorts                    []uint16          `json:"proxyOnlyTCPPorts,omitempty"`
	ProxyOnlyUDPPorts                    []uint16          `json:"proxyOnlyUDPPorts,omitempty"`
	AutoFakeIPWhitelist                  bool              `json:"autoFakeIPWhitelist,omitempty"`
	AutoFakeIPIncludeExternalIPProviders bool              `json:"autoFakeIPIncludeExternalIPProviders,omitempty"`
	UseTmpfsRules                        bool              `json:"useTmpfsRules,omitempty"`
	EnableHWID                           bool              `json:"enableHWID,omitempty"`
	AutoRefreshProxyIPs                  bool              `json:"autoRefreshProxyIPs"`
	AutoRefreshFakeIP                    bool              `json:"autoRefreshFakeIP"`
	MaintenanceIntervalMinutes           int               `json:"maintenanceIntervalMinutes"`
	Interfaces                           []InterfaceOption `json:"interfaces,omitempty"`
	InterfaceSource                      string            `json:"interfaceSource,omitempty"`
}

type InterfaceOption struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type InterfaceCatalog struct {
	Interfaces []InterfaceOption
	Source     string
}

// SettingsPatch uses pointers so omitted values are distinguishable from zero values.
type SettingsPatch struct {
	CoreRestartGuard                     *bool     `json:"coreRestartGuard,omitempty"`
	Language                             *string   `json:"language,omitempty"`
	Theme                                *string   `json:"theme,omitempty"`
	LogLevel                             *string   `json:"logLevel,omitempty"`
	UpdateChannel                        *string   `json:"updateChannel,omitempty"`
	CaptureMode                          *string   `json:"captureMode,omitempty"`
	StartOnBoot                          *bool     `json:"startOnBoot,omitempty"`
	AutoUpdate                           *bool     `json:"autoUpdate,omitempty"`
	OperatingMode                        *string   `json:"operatingMode,omitempty"`
	DNSMode                              *string   `json:"dnsMode,omitempty"`
	InterfaceMode                        *string   `json:"interfaceMode,omitempty"`
	AutoDetectWAN                        *bool     `json:"autoDetectWAN,omitempty"`
	AutoDetectLAN                        *bool     `json:"autoDetectLAN,omitempty"`
	InterceptRouterOutput                *bool     `json:"interceptRouterOutput,omitempty"`
	IncludedInterfaces                   *[]string `json:"includedInterfaces,omitempty"`
	ExcludedInterfaces                   *[]string `json:"excludedInterfaces,omitempty"`
	TUNStack                             *string   `json:"tunStack,omitempty"`
	TUNAddress                           *string   `json:"tunAddress,omitempty"`
	TUNMTU                               *uint32   `json:"tunMTU,omitempty"`
	RejectQUIC                           *bool     `json:"rejectQUIC,omitempty"`
	ReservedNetworks                     *[]string `json:"reservedNetworks,omitempty"`
	BypassSources                        *[]string `json:"bypassSources,omitempty"`
	BypassTCPPorts                       *[]uint16 `json:"bypassTCPPorts,omitempty"`
	BypassUDPPorts                       *[]uint16 `json:"bypassUDPPorts,omitempty"`
	ProxyOnlyTCPPorts                    *[]uint16 `json:"proxyOnlyTCPPorts,omitempty"`
	ProxyOnlyUDPPorts                    *[]uint16 `json:"proxyOnlyUDPPorts,omitempty"`
	AutoFakeIPWhitelist                  *bool     `json:"autoFakeIPWhitelist,omitempty"`
	AutoFakeIPIncludeExternalIPProviders *bool     `json:"autoFakeIPIncludeExternalIPProviders,omitempty"`
	UseTmpfsRules                        *bool     `json:"useTmpfsRules,omitempty"`
	EnableHWID                           *bool     `json:"enableHWID,omitempty"`
	AutoRefreshProxyIPs                  *bool     `json:"autoRefreshProxyIPs,omitempty"`
	AutoRefreshFakeIP                    *bool     `json:"autoRefreshFakeIP,omitempty"`
	MaintenanceIntervalMinutes           *int      `json:"maintenanceIntervalMinutes,omitempty"`
}

type SettingsService interface {
	Settings(ctx context.Context) (Settings, error)
	UpdateSettings(ctx context.Context, patch SettingsPatch) (Settings, error)
}

// RawConfigDocument is the authenticated editor representation. Content can
// contain credentials: handlers set no-store, never log it, and never include it
// in mutation responses or error details.
type RawConfigDocument struct {
	Format          string      `json:"format"`
	Content         string      `json:"content"`
	Revision        string      `json:"revision"`
	UpdatedAt       time.Time   `json:"updatedAt,omitempty"`
	Profile         *ProfileRef `json:"profile,omitempty"`
	Engine          string      `json:"engine,omitempty"`
	Active          bool        `json:"active,omitempty"`
	AppliedRevision string      `json:"appliedRevision,omitempty"`
	Pending         bool        `json:"pending,omitempty"`
}

type RawConfigUpdate struct {
	Content  string `json:"content"`
	Revision string `json:"revision,omitempty"`
	// Apply selects what happens after the validated document is persisted:
	// save, reload, or restart. An omitted value retains the historical restart
	// behavior for API clients written before this field existed.
	Apply string `json:"apply,omitempty"`
}

type ConfigDiagnostic struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}

type ConfigValidation struct {
	Valid       bool               `json:"valid"`
	Diagnostics []ConfigDiagnostic `json:"diagnostics,omitempty"`
}

// ConfigSaveResult intentionally does not echo raw configuration content.
type ConfigSaveResult struct {
	Revision       string    `json:"revision"`
	UpdatedAt      time.Time `json:"updatedAt,omitempty"`
	ReloadRequired bool      `json:"reloadRequired"`
	Applied        bool      `json:"applied"`
	Apply          string    `json:"apply"`
}

type ConfigService interface {
	RawConfig(ctx context.Context) (RawConfigDocument, error)
	ValidateRawConfig(ctx context.Context, update RawConfigUpdate) (ConfigValidation, error)
	SaveRawConfig(ctx context.Context, update RawConfigUpdate) (ConfigSaveResult, error)
}

// ProfileConfigService exposes the same secret-safe editor contract for a
// specific active or inactive profile. The legacy ConfigService remains the
// active-profile alias for older clients.
type ProfileConfigService interface {
	ProfileConfig(ctx context.Context, id string) (RawConfigDocument, error)
	ValidateProfileConfig(ctx context.Context, id string, update RawConfigUpdate) (ConfigValidation, error)
	SaveProfileConfig(ctx context.Context, id string, update RawConfigUpdate) (ConfigSaveResult, error)
}

// Profile is safe to return to a browser. Source credentials and raw generated
// engine configuration are intentionally absent.
type Profile struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Engine              string    `json:"engine"`
	SourceKind          string    `json:"sourceKind"`
	HasSource           bool      `json:"hasSource"`
	SourceEnabled       bool      `json:"sourceEnabled"`
	Active              bool      `json:"active"`
	NodeCount           int       `json:"nodeCount,omitempty"`
	UpdateIntervalHours int       `json:"updateIntervalHours,omitempty"`
	UpdateIntervalAuto  bool      `json:"updateIntervalAuto,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt,omitzero"`
	LastCheckedAt       time.Time `json:"lastCheckedAt,omitzero"`
	NextUpdateAt        time.Time `json:"nextUpdateAt,omitzero"`
	LastError           string    `json:"lastError,omitempty"`
	Fingerprint         string    `json:"fingerprint,omitempty"`
	AppliedRevision     string    `json:"appliedRevision,omitempty"`
	PendingRevision     string    `json:"pendingRevision,omitempty"`
	PendingAt           time.Time `json:"pendingAt,omitzero"`
	RestartRequired     bool      `json:"restartRequired,omitempty"`
}

// ProfileDraft accepts a source URL on writes, but no API response includes it.
type ProfileDraft struct {
	Name                string `json:"name"`
	Engine              string `json:"engine,omitempty"`
	SourceURL           string `json:"sourceUrl,omitempty"`
	Content             string `json:"content,omitempty"`
	UpdateIntervalHours *int   `json:"updateIntervalHours,omitempty"`
}

type ProfilePatch struct {
	Name                *string `json:"name,omitempty"`
	Engine              *string `json:"engine,omitempty"`
	SourceURL           *string `json:"sourceUrl,omitempty"`
	Content             *string `json:"content,omitempty"`
	UpdateIntervalHours *int    `json:"updateIntervalHours,omitempty"`
	UpdateIntervalAuto  *bool   `json:"updateIntervalAuto,omitempty"`
	SourceEnabled       *bool   `json:"sourceEnabled,omitempty"`
}

type ProfileService interface {
	Profiles(ctx context.Context) ([]Profile, error)
	Profile(ctx context.Context, id string) (Profile, error)
	CreateProfile(ctx context.Context, draft ProfileDraft) (Profile, error)
	UpdateProfile(ctx context.Context, id string, patch ProfilePatch) (Profile, error)
	DeleteProfile(ctx context.Context, id string) error
	ActivateProfile(ctx context.Context, id string) (Profile, error)
	RefreshProfile(ctx context.Context, id string) (Profile, error)
	DetachProfileSource(ctx context.Context, id string) (Profile, error)
}

type ProfileActivationRequest struct {
	ConfirmRestart bool `json:"confirmRestart,omitempty"`
}

// ConfirmedProfileService is optional so embedders implementing the original
// ProfileService keep working. The production service uses it to reject an
// implicit disruptive switch while a core is running.
type ConfirmedProfileService interface {
	ActivateProfileWithRequest(ctx context.Context, id string, request ProfileActivationRequest) (Profile, error)
}

// ProxySubscription is a secret-free view of one boxctl-managed Mihomo proxy
// provider. URLs, share links and header values are write-only.
type ProxySubscription struct {
	ID                  string    `json:"id"`
	Engine              string    `json:"engine"`
	Name                string    `json:"name"`
	ProviderName        string    `json:"providerName"`
	SourceKind          string    `json:"sourceKind"`
	Enabled             bool      `json:"enabled"`
	HeaderNames         []string  `json:"headerNames,omitempty"`
	UpdateIntervalHours int       `json:"updateIntervalHours"`
	UpdateIntervalAuto  bool      `json:"updateIntervalAuto,omitempty"`
	ProxyCount          int       `json:"proxyCount,omitempty"`
	UploadBytes         int64     `json:"uploadBytes,omitempty"`
	DownloadBytes       int64     `json:"downloadBytes,omitempty"`
	TotalBytes          int64     `json:"totalBytes,omitempty"`
	ExpiresAt           time.Time `json:"expiresAt,omitzero"`
	UpdatedAt           time.Time `json:"updatedAt,omitzero"`
	LastCheckedAt       time.Time `json:"lastCheckedAt,omitzero"`
	NextUpdateAt        time.Time `json:"nextUpdateAt,omitzero"`
	LastError           string    `json:"lastError,omitempty"`
}

type ProxySubscriptionDraft struct {
	Engine              string            `json:"engine,omitempty"`
	Name                string            `json:"name"`
	SourceURL           string            `json:"sourceUrl,omitempty"`
	ShareLinks          string            `json:"shareLinks,omitempty"`
	UpdateIntervalHours *int              `json:"updateIntervalHours,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
}

type ProxySubscriptionPatch struct {
	Name                *string            `json:"name,omitempty"`
	SourceURL           *string            `json:"sourceUrl,omitempty"`
	ShareLinks          *string            `json:"shareLinks,omitempty"`
	UpdateIntervalHours *int               `json:"updateIntervalHours,omitempty"`
	UpdateIntervalAuto  *bool              `json:"updateIntervalAuto,omitempty"`
	Enabled             *bool              `json:"enabled,omitempty"`
	Headers             *map[string]string `json:"headers,omitempty"`
}

type ProxySubscriptionService interface {
	ProxySubscriptions(ctx context.Context) ([]ProxySubscription, error)
	ProxySubscription(ctx context.Context, id string) (ProxySubscription, error)
	CreateProxySubscription(ctx context.Context, draft ProxySubscriptionDraft) (ProxySubscription, error)
	UpdateProxySubscription(ctx context.Context, id string, patch ProxySubscriptionPatch) (ProxySubscription, error)
	DeleteProxySubscription(ctx context.Context, id string) error
	RefreshProxySubscription(ctx context.Context, id string) (ProxySubscription, error)
}

// RuleList is safe summary metadata for a local rule list. Revision is an opaque
// optimistic-concurrency token owned by the backing service.
type RuleList struct {
	ID              string    `json:"id"`
	Engine          string    `json:"engine"`
	Name            string    `json:"name"`
	Format          string    `json:"format"`
	Enabled         bool      `json:"enabled"`
	RuleCount       int       `json:"ruleCount,omitempty"`
	Revision        string    `json:"revision"`
	UpdatedAt       time.Time `json:"updatedAt,omitempty"`
	ProviderName    string    `json:"providerName,omitempty"`
	InConfig        bool      `json:"inConfig"`
	ConfigNameTaken bool      `json:"configNameTaken"`
	InUse           bool      `json:"inUse"`
}

type RuleListDocument struct {
	RuleList
	Content string `json:"content"`
}

type RuleListDraft struct {
	Engine  string `json:"engine,omitempty"`
	Name    string `json:"name"`
	Format  string `json:"format"`
	Enabled bool   `json:"enabled"`
	Content string `json:"content"`
}

type RuleListUpdate struct {
	Name     *string `json:"name,omitempty"`
	Format   *string `json:"format,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
	Content  *string `json:"content,omitempty"`
	Revision string  `json:"revision"`
}

// RuleListService implements optimistic concurrency. UpdateRuleList and
// DeleteRuleList should return ErrConflict when revision is stale.
type RuleListService interface {
	RuleLists(ctx context.Context) ([]RuleList, error)
	RuleList(ctx context.Context, id string) (RuleListDocument, error)
	CreateRuleList(ctx context.Context, draft RuleListDraft) (RuleListDocument, error)
	UpdateRuleList(ctx context.Context, id string, update RuleListUpdate) (RuleListDocument, error)
	DeleteRuleList(ctx context.Context, id, revision string) error
	AddRuleListToConfig(ctx context.Context, id string) (RuleListDocument, error)
}

// FakeIPWhitelistDocument is the public, CIDR-only representation of the
// destination pool captured alongside the configured fake-IP ranges. It must
// not contain raw engine configuration or provider credentials.
type FakeIPWhitelistDocument struct {
	Engine          string     `json:"engine,omitempty"`
	ManualContent   string     `json:"manualContent"`
	GeneratedCIDRs  []string   `json:"generatedCIDRs"`
	FakeIPRanges    []string   `json:"fakeIPRanges"`
	EffectiveCIDRs  []string   `json:"effectiveCIDRs"`
	ManualCount     int        `json:"manualCount"`
	GeneratedCount  int        `json:"generatedCount"`
	EffectiveCount  int        `json:"effectiveCount"`
	Revision        string     `json:"revision"`
	GeneratedAt     *time.Time `json:"generatedAt,omitempty"`
	Applicable      bool       `json:"applicable"`
	Selective       bool       `json:"selective"`
	Applied         bool       `json:"applied"`
	RestartRequired bool       `json:"restartRequired"`
	Warnings        []string   `json:"warnings"`
}

// FakeIPWhitelistUpdate keeps the optimistic-concurrency token out of the JSON
// body. The handler populates Revision exclusively from If-Match.
type FakeIPWhitelistUpdate struct {
	ManualContent string `json:"manualContent"`
	Revision      string `json:"-"`
}

// FakeIPWhitelistService owns parsing, validation, generation and application
// of the CIDR document. Mutations should return ErrConflict for stale revisions.
type FakeIPWhitelistService interface {
	FakeIPWhitelist(ctx context.Context) (FakeIPWhitelistDocument, error)
	UpdateFakeIPWhitelist(ctx context.Context, update FakeIPWhitelistUpdate) (FakeIPWhitelistDocument, error)
	RegenerateFakeIPWhitelist(ctx context.Context, revision string) (FakeIPWhitelistDocument, error)
}

// BackupArchive is an authenticated binary export. Data may contain credentials
// and is therefore never included in JSON, logs, or error messages.
type BackupArchive struct {
	Filename string
	Data     []byte `json:"-"`
}

type BackupExportOptions struct {
	IncludeAdminPassword  bool `json:"includeAdminPassword"`
	IncludeProviderCaches bool `json:"includeProviderCaches"`
	IncludeDashboardUI    bool `json:"includeDashboardUI"`
}

type BackupImport struct {
	Filename string
	Data     []byte `json:"-"`
}

type BackupImportResult struct {
	Imported        bool     `json:"imported"`
	RestartRequired bool     `json:"restartRequired"`
	CoreRestarted   bool     `json:"coreRestarted"`
	SessionsRevoked bool     `json:"sessionsRevoked"`
	Warnings        []string `json:"warnings,omitempty"`
}

type BackupService interface {
	ExportBackup(ctx context.Context, options BackupExportOptions) (BackupArchive, error)
	ImportBackup(ctx context.Context, backup BackupImport) (BackupImportResult, error)
}

// CoreUpdateStatus contains only release identity and availability. Download
// URLs, asset digests and local filesystem paths remain server-side.
type CoreUpdateStatus struct {
	Engine          string `json:"engine,omitempty"`
	CurrentVersion  string `json:"currentVersion,omitempty"`
	LatestVersion   string `json:"latestVersion,omitempty"`
	Channel         string `json:"channel"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

type CoreUpdateResult struct {
	Engine          string `json:"engine,omitempty"`
	PreviousVersion string `json:"previousVersion,omitempty"`
	CurrentVersion  string `json:"currentVersion"`
	Restarted       bool   `json:"restarted"`
}

// CoreUpdateService performs verified, rollback-capable engine replacement.
// Implementations must serialize installs and restore the prior binary when
// the selected profile cannot start after replacement.
type CoreUpdateService interface {
	CoreUpdateStatus(ctx context.Context) (CoreUpdateStatus, error)
	InstallCoreUpdate(ctx context.Context) (CoreUpdateResult, error)
}

type EngineUpdateService interface {
	EngineUpdateStatus(ctx context.Context, engine string) (CoreUpdateStatus, error)
	InstallEngineUpdate(ctx context.Context, engine string) (CoreUpdateResult, error)
}

// ExternalDashboardStatus describes the optional on-disk Clash dashboard.
// Release URLs, checksums, filesystem paths, and the active core controller
// secret deliberately remain server-side.
type ExternalDashboardStatus struct {
	Name              string `json:"name"`
	Installed         bool   `json:"installed"`
	CurrentVersion    string `json:"currentVersion,omitempty"`
	LatestVersion     string `json:"latestVersion,omitempty"`
	UpdateAvailable   bool   `json:"updateAvailable"`
	UpdateCheckFailed bool   `json:"updateCheckFailed,omitempty"`
}

type ExternalDashboardResult struct {
	ExternalDashboardStatus
	Changed bool `json:"changed"`
}

type ExternalDashboardOpen struct {
	Path           string `json:"path"`
	ControllerPath string `json:"controllerPath"`
}

// ExternalDashboardService owns discovery and verified on-disk installation.
// The HTTP handler is kept separate so none of its controller credentials can
// accidentally enter an API DTO.
type ExternalDashboardService interface {
	ExternalDashboardStatus(ctx context.Context, checkUpdates bool) (ExternalDashboardStatus, error)
	InstallExternalDashboard(ctx context.Context) (ExternalDashboardResult, error)
	UpdateExternalDashboard(ctx context.Context) (ExternalDashboardResult, error)
	OpenExternalDashboard(ctx context.Context) (ExternalDashboardOpen, error)
}

// Capabilities drives both API behavior and UI page/action visibility.
type Capabilities struct {
	CoreName    string          `json:"coreName"`
	CoreVersion string          `json:"coreVersion,omitempty"`
	Pages       map[string]bool `json:"pages"`
	Actions     map[string]bool `json:"actions"`
	Features    map[string]bool `json:"features,omitempty"`
}

type ProxyGroup struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Icon     string        `json:"icon,omitempty"`
	Selected string        `json:"selected,omitempty"`
	Options  []ProxyOption `json:"options,omitempty"`
	History  []DelaySample `json:"history,omitempty"`
}

type ProxyOption struct {
	Name    string        `json:"name"`
	Type    string        `json:"type,omitempty"`
	Icon    string        `json:"icon,omitempty"`
	UDP     bool          `json:"udp,omitempty"`
	DelayMS *int64        `json:"delayMs,omitempty"`
	Alive   *bool         `json:"alive,omitempty"`
	History []DelaySample `json:"history,omitempty"`
}

type DelaySample struct {
	Time    string `json:"time,omitempty"`
	DelayMS int64  `json:"delayMs"`
}

// ProxyDelayResult is a bounded latency sample returned by the selected core.
// The test URL is intentionally not echoed because it may contain sensitive
// query parameters.
type ProxyDelayResult struct {
	Proxy   string `json:"proxy"`
	DelayMS int64  `json:"delayMs"`
}

// ProviderKind is a backend-neutral provider category exposed by the API.
type ProviderKind string

const (
	ProviderProxy ProviderKind = "proxy"
	ProviderRule  ProviderKind = "rule"
)

// Provider contains only controller-safe metadata. In particular, native
// filesystem paths and source URLs are never part of the web contract.
type Provider struct {
	Name             string                    `json:"name"`
	Type             string                    `json:"type,omitempty"`
	VehicleType      string                    `json:"vehicleType,omitempty"`
	UpdatedAt        string                    `json:"updatedAt,omitempty"`
	ProxyCount       int                       `json:"proxyCount,omitempty"`
	RuleCount        int                       `json:"ruleCount,omitempty"`
	Behavior         string                    `json:"behavior,omitempty"`
	Format           string                    `json:"format,omitempty"`
	SubscriptionInfo *ProviderSubscriptionInfo `json:"subscriptionInfo,omitempty"`
	HealthCheck      *ProviderHealthCheck      `json:"healthCheck,omitempty"`
}

type ProviderSubscriptionInfo struct {
	UploadBytes   int64 `json:"uploadBytes,omitempty"`
	DownloadBytes int64 `json:"downloadBytes,omitempty"`
	TotalBytes    int64 `json:"totalBytes,omitempty"`
	ExpireAt      int64 `json:"expireAt,omitempty"`
}

type ProviderHealthCheck struct {
	Enabled  bool  `json:"enabled"`
	Interval int64 `json:"interval,omitempty"`
	Lazy     bool  `json:"lazy,omitempty"`
}

type CoreTraffic struct {
	UploadRateBytes   int64     `json:"uploadRateBytes"`
	DownloadRateBytes int64     `json:"downloadRateBytes"`
	CapturedAt        time.Time `json:"capturedAt,omitempty"`
}

type CoreDashboard struct {
	Mode           string       `json:"mode,omitempty"`
	Groups         []ProxyGroup `json:"groups"`
	ProxyProviders []Provider   `json:"proxyProviders,omitempty"`
	RuleProviders  []Provider   `json:"ruleProviders,omitempty"`
	Traffic        *CoreTraffic `json:"traffic,omitempty"`
	CapturedAt     time.Time    `json:"capturedAt"`
}

type Connection struct {
	ID                string     `json:"id"`
	Network           string     `json:"network,omitempty"`
	Type              string     `json:"type,omitempty"`
	Source            string     `json:"source,omitempty"`
	SourceHostname    string     `json:"sourceHostname,omitempty"`
	Destination       string     `json:"destination,omitempty"`
	Host              string     `json:"host,omitempty"`
	Rule              string     `json:"rule,omitempty"`
	RulePayload       string     `json:"rulePayload,omitempty"`
	Chains            []string   `json:"chains,omitempty"`
	Outbound          string     `json:"outbound,omitempty"`
	UploadBytes       int64      `json:"uploadBytes,omitempty"`
	DownloadBytes     int64      `json:"downloadBytes,omitempty"`
	UploadRateBytes   int64      `json:"uploadRateBytes,omitempty"`
	DownloadRateBytes int64      `json:"downloadRateBytes,omitempty"`
	StartedAt         *time.Time `json:"startedAt,omitempty"`
	ClosedAt          *time.Time `json:"closedAt,omitempty"`
	DNSMode           string     `json:"dnsMode,omitempty"`
	SourceIP          string     `json:"sourceIP,omitempty"`
	SourcePort        string     `json:"sourcePort,omitempty"`
	DestinationIP     string     `json:"destinationIP,omitempty"`
	DestinationPort   string     `json:"destinationPort,omitempty"`
}

type ConnectionStreamSnapshot struct {
	Active             []Connection `json:"active"`
	Closed             []Connection `json:"closed,omitempty"`
	DownloadTotalBytes int64        `json:"downloadTotalBytes"`
	UploadTotalBytes   int64        `json:"uploadTotalBytes"`
	MemoryBytes        int64        `json:"memoryBytes,omitempty"`
	CapturedAt         time.Time    `json:"capturedAt"`
}

type Rule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload,omitempty"`
	Action  string `json:"action"`
	Size    int    `json:"size,omitempty"`
}

type LogQuery struct {
	Limit int
	Level string
}

type LogEntry struct {
	Time      time.Time      `json:"time"`
	Level     string         `json:"level"`
	Component string         `json:"component,omitempty"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// CoreService is a backend-neutral control plane. Adapters must translate these
// calls instead of exposing a raw Mihomo or sing-box client to web handlers.
type CoreService interface {
	Capabilities(ctx context.Context) (Capabilities, error)
	Health(ctx context.Context) (CoreHealth, error)
	Reload(ctx context.Context) error
	Dashboard(ctx context.Context) (CoreDashboard, error)
	StreamDashboard(ctx context.Context) (<-chan CoreDashboard, error)
	SetRoutingMode(ctx context.Context, mode string) error
	ProxyGroups(ctx context.Context) ([]ProxyGroup, error)
	SelectProxy(ctx context.Context, group, proxy string) error
	TestProxyDelay(ctx context.Context, proxy, testURL string, timeout time.Duration) (ProxyDelayResult, error)
	Providers(ctx context.Context, kind ProviderKind) ([]Provider, error)
	UpdateProvider(ctx context.Context, kind ProviderKind, name string) error
	Connections(ctx context.Context) ([]Connection, error)
	StreamConnections(ctx context.Context) (<-chan ConnectionStreamSnapshot, error)
	CloseConnection(ctx context.Context, id string) error
	CloseAllConnections(ctx context.Context) error
	Rules(ctx context.Context) ([]Rule, error)
	CoreLogs(ctx context.Context, query LogQuery) ([]LogEntry, error)
	StreamCoreLogs(ctx context.Context, query LogQuery) (<-chan LogEntry, error)
}

type SystemLogService interface {
	SystemLogs(ctx context.Context, query LogQuery) ([]LogEntry, error)
	StreamSystemLogs(ctx context.Context, query LogQuery) (<-chan LogEntry, error)
}

// FirewallService provides explicit recovery of owned gateway state.
type FirewallService interface {
	CleanupFirewall(ctx context.Context) error
}

// LifecycleService controls the selected engine without exposing its native API.
type LifecycleService interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Restart(ctx context.Context) error
}

// Services are all dependencies of the HTTP layer. Credentials and SessionSecrets
// are required; feature services may be nil and then return capability-safe 501s.
type Services struct {
	Credentials           CredentialService
	AdminSetup            AdminSetupService
	SessionSecrets        SessionSecretStore
	Status                StatusService
	Engines               EngineService
	Settings              SettingsService
	Config                ConfigService
	Profiles              ProfileService
	ProxySubscriptions    ProxySubscriptionService
	RuleLists             RuleListService
	FakeIPWhitelist       FakeIPWhitelistService
	Backups               BackupService
	CoreUpdates           CoreUpdateService
	ExternalDashboard     ExternalDashboardService
	ExternalDashboardHTTP http.Handler
	Core                  CoreService
	Lifecycle             LifecycleService
	Firewall              FirewallService
	SystemLogs            SystemLogService
}
