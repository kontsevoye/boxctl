package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/eventlog"
	"github.com/kontsevoye/boxctl/internal/state"
	"github.com/kontsevoye/boxctl/internal/web"
)

const (
	defaultCoreLogHistory      = 1_000
	maximumCoreLogHistory      = 5_000
	defaultCoreLogMessageBytes = 16 << 10
	maximumCoreLogMessageBytes = 1 << 20
)

// CoreBackend is the engine-neutral runtime/control surface needed by the web
// adapter. *engine.MihomoDriver satisfies this interface directly; a future
// sing-box driver can do the same without changing web handlers.
type CoreBackend interface {
	engine.Runtime
	engine.Control
	Capabilities() engine.Capabilities
}

// CoreServiceOptions contains only public presentation and bounded-memory
// settings. CoreName must not contain profile or controller data.
type CoreServiceOptions struct {
	CoreName                string
	SelectedEngine          func() string
	LogHistory              int
	MaxLogMessageBytes      int
	UnsafeExternalDashboard bool
}

// CoreService translates engine contracts into web's secret-free DTOs. It
// never inspects PreparedCore.Controller or reads native configuration.
type CoreService struct {
	core                    CoreBackend
	preparer                ActivePreparer
	lifecycle               *Lifecycle
	coreName                string
	selectedEngine          func() string
	logs                    *eventlog.Ring
	history                 int
	maxMessage              int
	unsafeExternalDashboard bool

	logContext context.Context
	cancelLogs context.CancelFunc
	logsDone   chan struct{}
	closeOnce  sync.Once
	closed     atomic.Bool

	dashboardMu          sync.Mutex
	dashboardSubscribers map[chan struct{}]struct{}
}

type coreLifecycleView struct {
	state             LifecycleState
	engine            string
	runtimeConfigPath string
	capture           engine.CapturePlan
	health            engine.HealthStatus
	startedAt         time.Time
	hasLastError      bool
}

// NewCoreService starts a bounded log collector. Close should be called during
// application shutdown so the collector and active SSE subscriptions stop.
func NewCoreService(lifecycle *Lifecycle, preparer ActivePreparer, core CoreBackend, options CoreServiceOptions) (*CoreService, error) {
	if lifecycle == nil || isNilInterface(preparer) || isNilInterface(core) {
		return nil, errors.New("core service dependencies are incomplete")
	}
	if strings.ContainsAny(options.CoreName, "\r\n") || len(options.CoreName) > 128 {
		return nil, errors.New("core service name is invalid")
	}
	history := options.LogHistory
	if history <= 0 {
		history = defaultCoreLogHistory
	}
	if history > maximumCoreLogHistory {
		history = maximumCoreLogHistory
	}
	maxMessage := options.MaxLogMessageBytes
	if maxMessage <= 0 {
		maxMessage = defaultCoreLogMessageBytes
	}
	if maxMessage > maximumCoreLogMessageBytes {
		maxMessage = maximumCoreLogMessageBytes
	}
	logContext, cancelLogs := context.WithCancel(context.Background())
	service := &CoreService{
		core:                    core,
		preparer:                preparer,
		lifecycle:               lifecycle,
		coreName:                strings.TrimSpace(options.CoreName),
		selectedEngine:          options.SelectedEngine,
		logs:                    eventlog.New(history),
		history:                 history,
		maxMessage:              maxMessage,
		unsafeExternalDashboard: options.UnsafeExternalDashboard,
		logContext:              logContext,
		cancelLogs:              cancelLogs,
		logsDone:                make(chan struct{}),
		dashboardSubscribers:    make(map[chan struct{}]struct{}),
	}
	go service.collectLogs(core.Logs())
	return service, nil
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Close stops only adapter-owned log collection. Core process lifecycle remains
// owned by Lifecycle.
func (service *CoreService) Close() error {
	if service == nil {
		return nil
	}
	service.closeOnce.Do(func() {
		service.closed.Store(true)
		service.cancelLogs()
		<-service.logsDone
	})
	return nil
}

func (service *CoreService) collectLogs(source <-chan engine.LogEntry) {
	defer close(service.logsDone)
	for {
		select {
		case <-service.logContext.Done():
			return
		case entry, ok := <-source:
			if !ok {
				return
			}
			service.logs.Append(eventlog.Entry{
				Timestamp: entry.Time,
				Level:     coreLogLevel(entry),
				Component: coreLogComponent(entry.Stream),
				Message:   safeCoreLogMessage(entry.Message, service.maxMessage),
			})
		}
	}
}

func (service *CoreService) Capabilities(ctx context.Context) (web.Capabilities, error) {
	if err := service.available(ctx); err != nil {
		return web.Capabilities{}, err
	}
	capabilities := service.core.Capabilities()
	snapshot := service.lifecycleView()
	engineName := service.name(snapshot)
	mihomoResources := engineName == state.EngineMihomo
	externalDashboard := service.unsafeExternalDashboard && mihomoResources
	return web.Capabilities{
		CoreName:    service.name(snapshot),
		CoreVersion: snapshot.health.Version,
		Pages: map[string]bool{
			"status":      true,
			"profiles":    true,
			"rawConfig":   true,
			"ruleLists":   mihomoResources,
			"backups":     true,
			"settings":    true,
			"systemLogs":  true,
			"proxies":     capabilities.Groups,
			"connections": capabilities.Connections,
			"rules":       capabilities.Rules,
			"coreLogs":    capabilities.ProcessLogs,
		},
		Actions: map[string]bool{
			"createRuleList":      mihomoResources,
			"editRuleList":        mihomoResources,
			"deleteRuleList":      mihomoResources,
			"exportBackup":        true,
			"importBackup":        true,
			"updateCore":          true,
			"reloadCore":          capabilities.HotReload,
			"selectProxy":         capabilities.Groups && capabilities.Selection,
			"testProxyDelay":      capabilities.Delay,
			"updateProxyProvider": capabilities.ProxyProviders,
			"updateRuleProvider":  capabilities.RuleProviders,
			"closeConnection":     capabilities.Connections && capabilities.CloseConnection,
			"closeAllConnections": capabilities.Connections && capabilities.CloseAllConnections,
			"setRoutingMode":      capabilities.RoutingMode,
			"toggleRule":          capabilities.RuleMutation,
			"startService":        true,
			"stopService":         true,
			"restartService":      true,
		},
		Features: map[string]bool{
			"hotReload":           capabilities.HotReload,
			"proxies":             capabilities.Proxies,
			"groups":              capabilities.Groups,
			"selection":           capabilities.Selection,
			"delay":               capabilities.Delay,
			"proxyProviders":      capabilities.ProxyProviders,
			"ruleProviders":       capabilities.RuleProviders,
			"rules":               capabilities.Rules,
			"connections":         capabilities.Connections,
			"closeConnection":     capabilities.CloseConnection,
			"closeAllConnections": capabilities.CloseAllConnections,
			"routingMode":         capabilities.RoutingMode,
			"trafficStream":       capabilities.TrafficStream,
			"ruleMutation":        capabilities.RuleMutation,
			"processLogs":         capabilities.ProcessLogs,
			"externalDashboard":   externalDashboard,
		},
	}, nil
}

func (service *CoreService) Health(ctx context.Context) (web.CoreHealth, error) {
	if err := service.available(ctx); err != nil {
		return web.CoreHealth{}, err
	}
	snapshot := service.lifecycleView()
	status, err := service.core.Health(ctx)
	state := snapshot.state
	if state == "" {
		state = LifecycleStopped
	}
	if status.Running && state == LifecycleStopped {
		state = LifecycleRunning
	}
	if !status.Running && state == LifecycleRunning {
		state = LifecycleFailed
	}
	since := status.StartedAt
	if since.IsZero() {
		since = snapshot.startedAt
	}
	version := status.Version
	if version == "" {
		version = snapshot.health.Version
	}
	result := web.CoreHealth{
		Name:    service.name(snapshot),
		Version: version,
		State:   string(state),
		Since:   since,
	}
	switch {
	case err != nil:
		result.LastError = "core health check failed"
	case status.LastExitError != "":
		result.LastError = "core process exited unexpectedly"
	case snapshot.hasLastError:
		result.LastError = "core lifecycle operation failed"
	}
	if err != nil {
		if contextError := contextCause(ctx, err); contextError != nil {
			return result, contextError
		}
		return result, errors.Join(web.ErrUnavailable, errors.New("core health check failed"))
	}
	return result, nil
}

// Reload serializes with lifecycle start/stop, prepares a new immutable runtime
// copy, rejects platform-plan changes that require a restart, and hot-reloads
// the running backend.
func (service *CoreService) Reload(ctx context.Context) error {
	if err := service.available(ctx); err != nil {
		return err
	}
	if !service.core.Capabilities().HotReload {
		return unsupportedCore("reload")
	}
	if err := service.lifecycle.lockOperation(ctx); err != nil {
		return err
	}
	defer service.lifecycle.opMu.Unlock()
	service.lifecycle.defaults()
	operationContext, cancelOperation := context.WithTimeout(ctx, service.lifecycle.PrepareTimeout)
	defer cancelOperation()
	current := service.lifecycleView()
	if current.state != LifecycleRunning {
		return errors.Join(
			engine.ErrNotRunning,
			web.ErrConflict,
			&web.PublicError{Status: 409, Code: "core_not_running", Message: "Core must be running before reload"},
		)
	}
	prepared, err := service.preparer.PrepareActive(operationContext)
	if err != nil {
		return fmt.Errorf("prepare active core for reload: %w", err)
	}
	adopted := false
	defer func() {
		if !adopted {
			removeFailedReloadRuntime(prepared, current)
		}
	}()
	if current.engine != "" && prepared.Engine != current.engine {
		return reloadRequiresRestart()
	}
	if !sameCapturePlan(current.capture, prepared.Capture) {
		return reloadRequiresRestart()
	}
	if err := service.core.Reload(operationContext, prepared); err != nil {
		return translateCoreError(err)
	}
	service.lifecycle.mu.Lock()
	service.lifecycle.snap.Prepared = prepared
	service.lifecycle.snap.LastError = ""
	service.lifecycle.snap.LastChecked = time.Now().UTC()
	service.lifecycle.mu.Unlock()
	adopted = true
	service.invalidateDashboard()
	return nil
}

// removeFailedReloadRuntime removes only the private Mihomo YAML created for
// this reload attempt. The active runtime and user-owned source config are
// explicitly excluded even if a broken preparer returns the same path.
func removeFailedReloadRuntime(prepared engine.PreparedCore, current coreLifecycleView) {
	runtimePath := filepath.Clean(prepared.RuntimeConfigPath)
	if runtimePath == "." || runtimePath == "" ||
		runtimePath == filepath.Clean(prepared.SourceConfigPath) ||
		runtimePath == filepath.Clean(current.runtimeConfigPath) ||
		prepared.Engine != "mihomo" {
		return
	}
	removeOneShotRuntime(prepared)
}

// Dashboard returns a controller-safe snapshot of state used by the integrated
// proxy dashboard. Native paths, provider URLs and controller credentials are
// deliberately excluded by the web DTO allow-list.
func (service *CoreService) Dashboard(ctx context.Context) (web.CoreDashboard, error) {
	if err := service.available(ctx); err != nil {
		return web.CoreDashboard{}, err
	}
	capabilities := service.core.Capabilities()
	result := web.CoreDashboard{CapturedAt: time.Now().UTC()}
	if capabilities.RoutingMode {
		mode, err := service.core.RoutingMode(ctx)
		if err != nil {
			return web.CoreDashboard{}, translateCoreError(err)
		}
		result.Mode = string(mode)
	}
	if capabilities.Groups {
		groups, err := service.ProxyGroups(ctx)
		if err != nil {
			return web.CoreDashboard{}, err
		}
		result.Groups = groups
	} else {
		result.Groups = []web.ProxyGroup{}
	}
	if capabilities.ProxyProviders {
		providers, err := service.Providers(ctx, web.ProviderProxy)
		if err != nil {
			return web.CoreDashboard{}, err
		}
		result.ProxyProviders = providers
	}
	if capabilities.RuleProviders {
		providers, err := service.Providers(ctx, web.ProviderRule)
		if err != nil {
			return web.CoreDashboard{}, err
		}
		result.RuleProviders = providers
	}
	return result, nil
}

// StreamDashboard emits one complete snapshot and then only core-originated
// traffic events or snapshots invalidated by successful control mutations. It
// intentionally has no timer-based metadata refresh loop.
func (service *CoreService) StreamDashboard(ctx context.Context) (<-chan web.CoreDashboard, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	// Subscribe before taking the initial controller snapshot. A successful
	// control mutation in the gap between those operations is then either
	// already reflected by Dashboard or remains queued for the stream loop; it
	// can never be silently lost.
	invalidation, unsubscribe := service.subscribeDashboard()
	initial, err := service.Dashboard(ctx)
	if err != nil {
		unsubscribe()
		return nil, err
	}

	var traffic <-chan engine.TrafficSnapshot
	if service.core.Capabilities().TrafficStream {
		traffic, err = service.core.StreamTraffic(ctx)
		if err != nil {
			unsubscribe()
			return nil, translateCoreError(err)
		}
		if traffic == nil {
			unsubscribe()
			return nil, errors.Join(web.ErrUnavailable, errors.New("traffic stream is unavailable"))
		}
	}
	stream := make(chan web.CoreDashboard, 1)
	go func() {
		defer close(stream)
		defer unsubscribe()
		current := initial
		if !sendDashboard(ctx, service.logContext, stream, current) {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-service.logContext.Done():
				return
			case update, ok := <-traffic:
				if !ok {
					// Closing the SSE response makes EventSource reconnect, which in
					// turn establishes a fresh native Mihomo WebSocket. Keeping an
					// otherwise healthy-looking SSE connection open here would leave
					// traffic permanently frozen after one upstream disconnect.
					return
				}
				current.Traffic = &web.CoreTraffic{
					UploadRateBytes: update.UploadRateBytes, DownloadRateBytes: update.DownloadRateBytes, CapturedAt: update.CapturedAt.UTC(),
				}
				if !sendDashboard(ctx, service.logContext, stream, current) {
					return
				}
			case <-invalidation:
				next, snapshotErr := service.Dashboard(ctx)
				if snapshotErr != nil {
					return
				}
				next.Traffic = current.Traffic
				current = next
				if !sendDashboard(ctx, service.logContext, stream, current) {
					return
				}
			}
		}
	}()
	return stream, nil
}

func sendDashboard(ctx, serviceContext context.Context, stream chan<- web.CoreDashboard, snapshot web.CoreDashboard) bool {
	select {
	case stream <- snapshot:
		return true
	case <-ctx.Done():
		return false
	case <-serviceContext.Done():
		return false
	}
}

func (service *CoreService) subscribeDashboard() (<-chan struct{}, func()) {
	updates := make(chan struct{}, 1)
	service.dashboardMu.Lock()
	service.dashboardSubscribers[updates] = struct{}{}
	service.dashboardMu.Unlock()
	return updates, func() {
		service.dashboardMu.Lock()
		delete(service.dashboardSubscribers, updates)
		service.dashboardMu.Unlock()
	}
}

func (service *CoreService) invalidateDashboard() {
	service.dashboardMu.Lock()
	defer service.dashboardMu.Unlock()
	for subscriber := range service.dashboardSubscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
}

func (service *CoreService) SetRoutingMode(ctx context.Context, value string) error {
	if err := service.available(ctx); err != nil {
		return err
	}
	if !service.core.Capabilities().RoutingMode {
		return unsupportedCore("routing mode")
	}
	mode := engine.RoutingMode(strings.ToLower(strings.TrimSpace(value)))
	if !mode.Valid() {
		return &web.PublicError{Status: 400, Code: "invalid_routing_mode", Message: "Routing mode must be rule, global or direct"}
	}
	if err := service.core.SetRoutingMode(ctx, mode); err != nil {
		return translateCoreError(err)
	}
	service.invalidateDashboard()
	return nil
}

func (service *CoreService) ProxyGroups(ctx context.Context) ([]web.ProxyGroup, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	if !service.core.Capabilities().Groups {
		return nil, unsupportedCore("proxy groups")
	}
	groups, err := service.core.Groups(ctx)
	if err != nil {
		return nil, translateCoreError(err)
	}
	result := make([]web.ProxyGroup, 0, len(groups))
	for _, group := range groups {
		optionMetadata := make(map[string]engine.Proxy, len(group.Options))
		for _, option := range group.Options {
			optionMetadata[option.Name] = option
		}
		options := make([]web.ProxyOption, 0, len(group.Members))
		for _, member := range group.Members {
			option := optionMetadata[member]
			options = append(options, web.ProxyOption{
				Name: member, Type: option.Type, Icon: safeProxyIcon(option.Icon), UDP: option.UDP, DelayMS: latestProxyDelay(option.History), Alive: option.Alive,
				History: webDelayHistory(option.History),
			})
		}
		result = append(result, web.ProxyGroup{
			Name: group.Name, Type: group.Type, Icon: safeProxyIcon(group.Icon), Selected: group.Now, Options: options, History: webDelayHistory(group.History),
		})
	}
	sort.SliceStable(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result, nil
}

func safeProxyIcon(value string) string {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	return value
}

func webDelayHistory(history []engine.DelaySample) []web.DelaySample {
	result := make([]web.DelaySample, 0, len(history))
	for _, sample := range history {
		if sample.Delay < 0 {
			continue
		}
		result = append(result, web.DelaySample{Time: sample.Time, DelayMS: int64(sample.Delay)})
	}
	return result
}

func latestProxyDelay(history []engine.DelaySample) *int64 {
	if len(history) == 0 {
		return nil
	}
	delay := history[len(history)-1].Delay
	if delay <= 0 {
		return nil
	}
	result := int64(delay)
	return &result
}

func (service *CoreService) SelectProxy(ctx context.Context, group, proxy string) error {
	if err := service.available(ctx); err != nil {
		return err
	}
	if !service.core.Capabilities().Selection {
		return unsupportedCore("proxy selection")
	}
	if err := service.core.Select(ctx, group, proxy); err != nil {
		return translateCoreError(err)
	}
	service.invalidateDashboard()
	return nil
}

func (service *CoreService) TestProxyDelay(ctx context.Context, proxy, testURL string, timeout time.Duration) (web.ProxyDelayResult, error) {
	if err := service.available(ctx); err != nil {
		return web.ProxyDelayResult{}, err
	}
	if !service.core.Capabilities().Delay {
		return web.ProxyDelayResult{}, unsupportedCore("proxy delay tests")
	}
	delay, err := service.core.Delay(ctx, proxy, testURL, timeout)
	if err != nil {
		return web.ProxyDelayResult{}, translateCoreError(err)
	}
	service.invalidateDashboard()
	return web.ProxyDelayResult{Proxy: proxy, DelayMS: delay.Milliseconds()}, nil
}

func (service *CoreService) Providers(ctx context.Context, kind web.ProviderKind) ([]web.Provider, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	engineKind, supported, err := service.providerKind(kind)
	if err != nil {
		return nil, err
	}
	if !supported {
		return nil, unsupportedCore(string(kind) + " providers")
	}
	providers, err := service.core.Providers(ctx, engineKind)
	if err != nil {
		return nil, translateCoreError(err)
	}
	result := make([]web.Provider, 0, len(providers))
	for _, provider := range providers {
		item := web.Provider{
			Name: provider.Name, Type: provider.Type, VehicleType: provider.VehicleType, UpdatedAt: provider.UpdatedAt,
			ProxyCount: provider.ProxyCount, RuleCount: provider.RuleCount, Behavior: provider.Behavior, Format: provider.Format,
		}
		if provider.SubscriptionInfo != nil {
			item.SubscriptionInfo = &web.ProviderSubscriptionInfo{
				UploadBytes: provider.SubscriptionInfo.Upload, DownloadBytes: provider.SubscriptionInfo.Download,
				TotalBytes: provider.SubscriptionInfo.Total, ExpireAt: provider.SubscriptionInfo.Expire,
			}
		}
		if provider.HealthCheck.Enabled || provider.HealthCheck.Interval > 0 || provider.HealthCheck.Lazy {
			item.HealthCheck = &web.ProviderHealthCheck{
				Enabled: provider.HealthCheck.Enabled, Interval: provider.HealthCheck.Interval, Lazy: provider.HealthCheck.Lazy,
			}
		}
		result = append(result, item)
	}
	sort.SliceStable(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result, nil
}

func (service *CoreService) UpdateProvider(ctx context.Context, kind web.ProviderKind, name string) error {
	if err := service.available(ctx); err != nil {
		return err
	}
	engineKind, supported, err := service.providerKind(kind)
	if err != nil {
		return err
	}
	if !supported {
		return unsupportedCore(string(kind) + " providers")
	}
	if err := service.core.UpdateProvider(ctx, engineKind, name); err != nil {
		return translateCoreError(err)
	}
	service.invalidateDashboard()
	return nil
}

func (service *CoreService) providerKind(kind web.ProviderKind) (engine.ProviderKind, bool, error) {
	capabilities := service.core.Capabilities()
	switch kind {
	case web.ProviderProxy:
		return engine.ProviderProxy, capabilities.ProxyProviders, nil
	case web.ProviderRule:
		return engine.ProviderRule, capabilities.RuleProviders, nil
	default:
		return "", false, &web.PublicError{Status: 400, Code: "invalid_provider_kind", Message: "Provider kind must be proxy or rule"}
	}
}

func (service *CoreService) Connections(ctx context.Context) ([]web.Connection, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	if !service.core.Capabilities().Connections {
		return nil, unsupportedCore("connections")
	}
	snapshot, err := service.core.Connections(ctx)
	if err != nil {
		return nil, translateCoreError(err)
	}
	return webConnections(snapshot, nil, 0), nil
}

// StreamConnections translates consecutive native snapshots into a stable web
// stream and derives per-connection rates from cumulative Mihomo counters.
func (service *CoreService) StreamConnections(ctx context.Context) (<-chan web.ConnectionStreamSnapshot, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	if !service.core.Capabilities().Connections {
		return nil, unsupportedCore("connections")
	}
	snapshots, err := service.core.StreamConnections(ctx, time.Second)
	if err != nil {
		return nil, translateCoreError(err)
	}
	if snapshots == nil {
		return nil, errors.Join(web.ErrUnavailable, errors.New("connection stream is unavailable"))
	}

	stream := make(chan web.ConnectionStreamSnapshot, 1)
	go func() {
		defer close(stream)
		var previous map[string]connectionCounters
		var previousConnections map[string]web.Connection
		closed := make([]web.Connection, 0)
		var previousAt time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case snapshot, ok := <-snapshots:
				if !ok {
					return
				}
				capturedAt := snapshot.CapturedAt
				if capturedAt.IsZero() {
					capturedAt = time.Now()
				}
				elapsed := time.Duration(0)
				if !previousAt.IsZero() {
					elapsed = capturedAt.Sub(previousAt)
				}
				connections := webConnections(snapshot, previous, elapsed)
				currentConnections := make(map[string]web.Connection, len(connections))
				for _, connection := range connections {
					currentConnections[connection.ID] = connection
				}
				for id, connection := range previousConnections {
					if _, stillActive := currentConnections[id]; stillActive {
						continue
					}
					closedAt := capturedAt.UTC()
					connection.ClosedAt = &closedAt
					connection.UploadRateBytes = 0
					connection.DownloadRateBytes = 0
					closed = append([]web.Connection{connection}, closed...)
				}
				if len(closed) > 500 {
					closed = closed[:500]
				}
				webSnapshot := web.ConnectionStreamSnapshot{
					Active: connections, Closed: append([]web.Connection(nil), closed...),
					DownloadTotalBytes: snapshot.DownloadTotal, UploadTotalBytes: snapshot.UploadTotal,
					MemoryBytes: snapshot.Memory, CapturedAt: capturedAt.UTC(),
				}
				previous = snapshotCounters(snapshot)
				previousConnections = currentConnections
				previousAt = capturedAt
				select {
				case stream <- webSnapshot:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return stream, nil
}

type connectionCounters struct {
	upload   int64
	download int64
}

func webConnections(snapshot engine.ConnectionsSnapshot, previous map[string]connectionCounters, elapsed time.Duration) []web.Connection {
	result := make([]web.Connection, 0, len(snapshot.Connections))
	for _, connection := range snapshot.Connections {
		outbound := ""
		if len(connection.Chains) > 0 {
			outbound = connection.Chains[0]
		}
		old, found := previous[connection.ID]
		result = append(result, web.Connection{
			ID:                connection.ID,
			Network:           connection.Metadata.Network,
			Type:              connection.Metadata.Type,
			Source:            joinCoreEndpoint(connection.Metadata.SourceIP, connection.Metadata.SourcePort),
			Destination:       joinCoreEndpoint(connection.Metadata.DestinationIP, connection.Metadata.DestinationPort),
			Host:              connection.Metadata.Host,
			Rule:              connection.Rule,
			RulePayload:       connection.RulePayload,
			Chains:            append([]string(nil), connection.Chains...),
			Outbound:          outbound,
			UploadBytes:       connection.Upload,
			DownloadBytes:     connection.Download,
			UploadRateBytes:   connectionRate(connection.Upload, old.upload, found, elapsed),
			DownloadRateBytes: connectionRate(connection.Download, old.download, found, elapsed),
			StartedAt:         optionalCoreTime(connection.Start),
			DNSMode:           connection.Metadata.DNSMode,
			SourceIP:          connection.Metadata.SourceIP,
			SourcePort:        connection.Metadata.SourcePort,
			DestinationIP:     connection.Metadata.DestinationIP,
			DestinationPort:   connection.Metadata.DestinationPort,
		})
	}
	return result
}

func snapshotCounters(snapshot engine.ConnectionsSnapshot) map[string]connectionCounters {
	result := make(map[string]connectionCounters, len(snapshot.Connections))
	for _, connection := range snapshot.Connections {
		result[connection.ID] = connectionCounters{upload: connection.Upload, download: connection.Download}
	}
	return result
}

func connectionRate(current, previous int64, found bool, elapsed time.Duration) int64 {
	if !found || current < previous || elapsed <= 0 {
		return 0
	}
	rate := float64(current-previous) / elapsed.Seconds()
	if rate >= math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(rate)
}

func (service *CoreService) CloseConnection(ctx context.Context, id string) error {
	if err := service.available(ctx); err != nil {
		return err
	}
	if !service.core.Capabilities().CloseConnection {
		return unsupportedCore("close connection")
	}
	return translateCoreError(service.core.CloseConnection(ctx, id))
}

func (service *CoreService) CloseAllConnections(ctx context.Context) error {
	if err := service.available(ctx); err != nil {
		return err
	}
	if !service.core.Capabilities().CloseAllConnections {
		return unsupportedCore("close all connections")
	}
	return translateCoreError(service.core.CloseAllConnections(ctx))
}

func (service *CoreService) Rules(ctx context.Context) ([]web.Rule, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	if !service.core.Capabilities().Rules {
		return nil, unsupportedCore("rules")
	}
	rules, err := service.core.Rules(ctx)
	if err != nil {
		return nil, translateCoreError(err)
	}
	result := make([]web.Rule, 0, len(rules))
	for index, rule := range rules {
		result = append(result, web.Rule{Index: index, Type: rule.Type, Payload: rule.Payload, Action: rule.Proxy, Size: rule.Size})
	}
	return result, nil
}

func (service *CoreService) CoreLogs(ctx context.Context, query web.LogQuery) ([]web.LogEntry, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	if !service.core.Capabilities().ProcessLogs {
		return nil, unsupportedCore("core logs")
	}
	limit, level := service.logQuery(query)
	entries := service.logs.Snapshot(0, limit)
	result := make([]web.LogEntry, 0, len(entries))
	for _, entry := range entries {
		if level == "" || strings.EqualFold(entry.Level, level) {
			result = append(result, coreEntryToWeb(entry))
		}
	}
	return result, nil
}

func (service *CoreService) StreamCoreLogs(ctx context.Context, query web.LogQuery) (<-chan web.LogEntry, error) {
	if err := service.available(ctx); err != nil {
		return nil, err
	}
	if !service.core.Capabilities().ProcessLogs {
		return nil, unsupportedCore("core logs")
	}
	limit, level := service.logQuery(query)
	streamContext, cancelContext := context.WithCancel(ctx)
	stopOnServiceClose := context.AfterFunc(service.logContext, cancelContext)
	snapshot, live, cancelSubscription := service.logs.Subscribe(streamContext, 0)
	if len(snapshot) > limit {
		snapshot = snapshot[len(snapshot)-limit:]
	}
	buffer := len(snapshot) + 64
	if maximum := service.history + 64; buffer > maximum {
		buffer = maximum
	}
	result := make(chan web.LogEntry, buffer)
	go func() {
		defer close(result)
		defer cancelSubscription()
		defer cancelContext()
		defer stopOnServiceClose()
		for _, entry := range snapshot {
			if level != "" && !strings.EqualFold(entry.Level, level) {
				continue
			}
			select {
			case result <- coreEntryToWeb(entry):
			case <-streamContext.Done():
				return
			}
		}
		for {
			select {
			case <-streamContext.Done():
				return
			case entry, ok := <-live:
				if !ok {
					return
				}
				if level != "" && !strings.EqualFold(entry.Level, level) {
					continue
				}
				select {
				case result <- coreEntryToWeb(entry):
				case <-streamContext.Done():
					return
				}
			}
		}
	}()
	return result, nil
}

func (service *CoreService) available(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if service == nil || service.closed.Load() {
		return web.ErrUnavailable
	}
	return nil
}

func (service *CoreService) name(snapshot coreLifecycleView) string {
	if snapshot.engine != "" {
		return snapshot.engine
	}
	if service.selectedEngine != nil {
		switch selected := strings.TrimSpace(service.selectedEngine()); selected {
		case state.EngineMihomo, state.EngineSingBox:
			return selected
		}
	}
	if service.coreName != "" {
		return service.coreName
	}
	return "core"
}

// lifecycleView intentionally copies only fields required by the web adapter;
// notably, it never reads or copies Prepared.Controller.
func (service *CoreService) lifecycleView() coreLifecycleView {
	service.lifecycle.mu.RLock()
	defer service.lifecycle.mu.RUnlock()
	return coreLifecycleView{
		state:             service.lifecycle.snap.State,
		engine:            service.lifecycle.snap.Prepared.Engine,
		runtimeConfigPath: service.lifecycle.snap.Prepared.RuntimeConfigPath,
		capture:           cloneCapturePlan(service.lifecycle.snap.Prepared.Capture),
		health:            service.lifecycle.snap.Health,
		startedAt:         service.lifecycle.snap.StartedAt,
		hasLastError:      service.lifecycle.snap.LastError != "",
	}
}

func cloneCapturePlan(plan engine.CapturePlan) engine.CapturePlan {
	plan.TUNAddresses = append([]netip.Prefix(nil), plan.TUNAddresses...)
	plan.FakeIPRanges = append([]netip.Prefix(nil), plan.FakeIPRanges...)
	plan.Destinations.CIDRs = append([]netip.Prefix(nil), plan.Destinations.CIDRs...)
	plan.EndpointBypassCIDRs = append([]netip.Prefix(nil), plan.EndpointBypassCIDRs...)
	return plan
}

func (service *CoreService) logQuery(query web.LogQuery) (int, string) {
	limit := normalizedLogLimit(query.Limit)
	if limit > service.history {
		limit = service.history
	}
	return limit, strings.ToLower(strings.TrimSpace(query.Level))
}

func coreEntryToWeb(entry eventlog.Entry) web.LogEntry {
	return web.LogEntry{
		Time: entry.Timestamp, Level: strings.ToLower(entry.Level), Component: entry.Component, Message: entry.Message,
	}
}

func coreLogLevel(entry engine.LogEntry) string {
	message := strings.ToLower(entry.Message)
	_, nativeStream := splitCoreLogStream(entry.Stream)
	switch {
	case nativeStream == "stderr" || strings.Contains(message, "level=error") || strings.HasPrefix(message, "[error]"):
		return "error"
	case strings.Contains(message, "level=warning") || strings.Contains(message, "level=warn") || strings.HasPrefix(message, "[warn]"):
		return "warn"
	case strings.Contains(message, "level=debug") || strings.HasPrefix(message, "[debug]"):
		return "debug"
	default:
		return "info"
	}
}

func coreLogComponent(stream string) string {
	engineName, nativeStream := splitCoreLogStream(stream)
	prefix := "core"
	if engineName != "" {
		prefix += "." + engineName
	}
	switch nativeStream {
	case "stdout", "stderr", "supervisor":
		return prefix + "." + nativeStream
	default:
		return prefix
	}
}

func splitCoreLogStream(stream string) (string, string) {
	engineName, nativeStream, found := strings.Cut(stream, "/")
	if !found || engineName == "" || nativeStream == "" {
		return "", stream
	}
	return engineName, nativeStream
}

func safeCoreLogMessage(message string, maximum int) string {
	message = strings.ToValidUTF8(message, "�")
	message = eventlog.RedactText(message)
	lower := strings.ToLower(message)
	for _, marker := range []string{
		"authorization", "bearer ", "basic ", "password", "passwd", "secret", "token", "credential",
		"private-key", "private_key", "apikey", "api-key", "source-url", "source_url", "external-controller",
	} {
		if strings.Contains(lower, marker) {
			return "[REDACTED]"
		}
	}
	if strings.Contains(message, "://") && strings.Contains(message, "@") {
		return "[REDACTED]"
	}
	if len(message) <= maximum {
		return message
	}
	message = message[:maximum]
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message + "…"
}

func joinCoreEndpoint(host, port string) string {
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func parseCoreTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func optionalCoreTime(value string) *time.Time {
	parsed := parseCoreTime(value)
	if parsed.IsZero() {
		return nil
	}
	return &parsed
}

func sameCapturePlan(left, right engine.CapturePlan) bool {
	if left.TCP != right.TCP || left.UDP != right.UDP || left.DNS != right.DNS ||
		left.TUNDevice != right.TUNDevice || left.TUNStack != right.TUNStack || left.TUNMTU != right.TUNMTU || left.LoopMark != right.LoopMark ||
		left.Capabilities != right.Capabilities || len(left.TUNAddresses) != len(right.TUNAddresses) ||
		left.Destinations.Mode != right.Destinations.Mode || len(left.Destinations.CIDRs) != len(right.Destinations.CIDRs) ||
		len(left.FakeIPRanges) != len(right.FakeIPRanges) || len(left.EndpointBypassCIDRs) != len(right.EndpointBypassCIDRs) {
		return false
	}
	for index := range left.TUNAddresses {
		if left.TUNAddresses[index] != right.TUNAddresses[index] {
			return false
		}
	}
	for index := range left.FakeIPRanges {
		if left.FakeIPRanges[index] != right.FakeIPRanges[index] {
			return false
		}
	}
	for index := range left.Destinations.CIDRs {
		if left.Destinations.CIDRs[index] != right.Destinations.CIDRs[index] {
			return false
		}
	}
	for index := range left.EndpointBypassCIDRs {
		if left.EndpointBypassCIDRs[index] != right.EndpointBypassCIDRs[index] {
			return false
		}
	}
	return true
}

func reloadRequiresRestart() error {
	return errors.Join(
		web.ErrConflict,
		&web.PublicError{Status: 409, Code: "reload_requires_restart", Message: "Capture changes require a full service restart"},
	)
}

func unsupportedCore(feature string) error {
	return errors.Join(
		engine.ErrUnsupported,
		&web.PublicError{Status: 501, Code: "unsupported", Message: "Core feature is not supported: " + feature},
	)
}

func translateCoreError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, engine.ErrUnsupported):
		return errors.Join(err, &web.PublicError{Status: 501, Code: "unsupported", Message: "Core feature is not supported"})
	case errors.Is(err, engine.ErrNotRunning):
		return errors.Join(err, web.ErrUnavailable)
	case errors.Is(err, engine.ErrAlreadyRunning):
		return errors.Join(err, web.ErrConflict)
	default:
		return err
	}
}

func contextCause(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

var (
	_ CoreBackend     = (*engine.MihomoDriver)(nil)
	_ web.CoreService = (*CoreService)(nil)
)
