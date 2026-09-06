package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/state"
)

// ExplicitProfilePreparer renders one profile without changing the persisted
// active selection. This is the critical preflight boundary for a safe engine
// switch.
type ExplicitProfilePreparer interface {
	PrepareProfile(context.Context, state.ActiveProfile) (engine.PreparedCore, error)
}

type committedProfileStatePublisher interface {
	PublishProfileState(context.Context, state.ActiveProfile, string) error
}

// ActiveControllerProvider exposes a loopback controller target without
// revealing it through any browser-facing DTO.
type ActiveControllerProvider interface {
	ActiveControllerEndpoint() (engine.ControllerEndpoint, error)
}

// EnginePreparer dispatches native preparation by the engine recorded on the
// profile. The active profile remains the sole persisted engine selection.
type EnginePreparer struct {
	Profiles  state.ProfileStore
	Preparers map[string]ExplicitProfilePreparer
	Legacy    ActivePreparer
}

func (preparer *EnginePreparer) PrepareActive(ctx context.Context) (engine.PreparedCore, error) {
	if preparer == nil {
		return engine.PreparedCore{}, errors.New("engine preparer is not initialized")
	}
	active, err := preparer.Profiles.Current()
	if errors.Is(err, fs.ErrNotExist) && preparer.Legacy != nil {
		return preparer.Legacy.PrepareActive(ctx)
	}
	if err != nil {
		return engine.PreparedCore{}, fmt.Errorf("read active profile: %w", err)
	}
	native := preparer.Preparers[active.Engine]
	if native == nil {
		return engine.PreparedCore{}, fmt.Errorf("%w: engine %q is not installed", engine.ErrUnsupported, active.Engine)
	}
	activeNative, ok := native.(ActivePreparer)
	if !ok {
		// Keep small test/extension preparers source-compatible. Production
		// native preparers implement PrepareActive so persistence happens only
		// for the authoritative selected profile.
		return preparer.PrepareProfile(ctx, active)
	}
	prepared, err := activeNative.PrepareActive(ctx)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	if prepared.Engine != active.Engine {
		engine.CleanupPreparedRuntime(prepared)
		return engine.PreparedCore{}, fmt.Errorf("prepared engine %q does not match profile engine %q", prepared.Engine, active.Engine)
	}
	return prepared, nil
}

func (preparer *EnginePreparer) PrepareProfile(ctx context.Context, profile state.ActiveProfile) (engine.PreparedCore, error) {
	if profile.Engine == "" {
		profile.Engine = state.EngineMihomo
	}
	native := preparer.Preparers[profile.Engine]
	if native == nil {
		return engine.PreparedCore{}, fmt.Errorf("%w: engine %q is not installed", engine.ErrUnsupported, profile.Engine)
	}
	prepared, err := native.PrepareProfile(ctx, profile)
	if err != nil {
		return engine.PreparedCore{}, err
	}
	if prepared.Engine != profile.Engine {
		engine.CleanupPreparedRuntime(prepared)
		return engine.PreparedCore{}, fmt.Errorf("prepared engine %q does not match profile engine %q", prepared.Engine, profile.Engine)
	}
	return prepared, nil
}

// PublishProfileState commits profile-derived companion state only after the
// ProfileSwitcher journal records the selected profile as committed. Engines
// without companion state intentionally have nothing to publish.
func (preparer *EnginePreparer) PublishProfileState(ctx context.Context, profile state.ActiveProfile, revision string) error {
	if profile.Engine == "" {
		profile.Engine = state.EngineMihomo
	}
	native := preparer.Preparers[profile.Engine]
	if native == nil {
		return fmt.Errorf("%w: engine %q is not installed", engine.ErrUnsupported, profile.Engine)
	}
	publisher, ok := native.(committedProfileStatePublisher)
	if !ok {
		return nil
	}
	return publisher.PublishProfileState(ctx, profile, revision)
}

// EngineHost is the stable process/control facade used by Lifecycle and the
// web layer. Stop and every control operation are routed to the backend which
// actually owns the live generation, never to a newly selected disk profile.
type EngineHost struct {
	backends map[string]CoreBackend
	selected func() string

	opMu    sync.Mutex
	mu      sync.RWMutex
	running string
	epoch   atomic.Uint64
	logs    chan engine.LogEntry
	logCtx  context.Context
	cancel  context.CancelFunc
	logWG   sync.WaitGroup
}

func NewEngineHost(backends map[string]CoreBackend, selected func() string) (*EngineHost, error) {
	if len(backends) == 0 {
		return nil, errors.New("engine host requires at least one backend")
	}
	copyBackends := make(map[string]CoreBackend, len(backends))
	for id, backend := range backends {
		if id == "" || isNilInterface(backend) {
			return nil, errors.New("engine host contains an invalid backend")
		}
		copyBackends[id] = backend
	}
	ctx, cancel := context.WithCancel(context.Background())
	host := &EngineHost{
		backends: copyBackends, selected: selected, logs: make(chan engine.LogEntry, 1024),
		logCtx: ctx, cancel: cancel,
	}
	for id, backend := range copyBackends {
		host.logWG.Add(1)
		go host.forwardLogs(id, backend.Logs())
	}
	return host, nil
}

func (host *EngineHost) Close() error {
	if host == nil || host.cancel == nil {
		return nil
	}
	host.cancel()
	host.logWG.Wait()
	return nil
}

func (host *EngineHost) forwardLogs(id string, source <-chan engine.LogEntry) {
	defer host.logWG.Done()
	for {
		select {
		case <-host.logCtx.Done():
			return
		case entry, ok := <-source:
			if !ok {
				return
			}
			entry.Stream = id + "/" + entry.Stream
			select {
			case host.logs <- entry:
			default:
			}
		}
	}
}

func (host *EngineHost) Backend(id string) (CoreBackend, bool) {
	backend, ok := host.backends[id]
	return backend, ok
}

func (host *EngineHost) SetAdopted(id string) error {
	if _, ok := host.backends[id]; !ok {
		return fmt.Errorf("unknown adopted engine %q", id)
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.running != "" && host.running != id {
		return engine.ErrAlreadyRunning
	}
	host.running = id
	host.epoch.Add(1)
	return nil
}

func (host *EngineHost) RunningEngine() string {
	host.mu.RLock()
	defer host.mu.RUnlock()
	return host.running
}

// ActiveControllerEndpoint returns only the controller owned by the live
// generation.  The selected profile is deliberately ignored: during a safe
// profile switch it can briefly differ from the process which actually owns
// the Clash-compatible API listener.
func (host *EngineHost) ActiveControllerEndpoint() (engine.ControllerEndpoint, error) {
	backend, _, err := host.runningBackend()
	if err != nil {
		return engine.ControllerEndpoint{}, err
	}
	provider, ok := backend.(ActiveControllerProvider)
	if !ok {
		return engine.ControllerEndpoint{}, engine.ErrUnsupported
	}
	return provider.ActiveControllerEndpoint()
}

func (host *EngineHost) RuntimeEpoch() uint64 { return host.epoch.Load() }

func (host *EngineHost) selectedEngine() string {
	if host.selected != nil {
		if id := host.selected(); id != "" {
			return id
		}
	}
	return state.EngineMihomo
}

func (host *EngineHost) Start(ctx context.Context, prepared engine.PreparedCore) error {
	host.opMu.Lock()
	defer host.opMu.Unlock()
	backend, ok := host.backends[prepared.Engine]
	if !ok {
		return fmt.Errorf("%w: engine %q is not installed", engine.ErrUnsupported, prepared.Engine)
	}
	host.mu.RLock()
	running := host.running
	host.mu.RUnlock()
	if running != "" {
		return engine.ErrAlreadyRunning
	}
	if err := backend.Start(ctx, prepared); err != nil {
		return err
	}
	host.mu.Lock()
	host.running = prepared.Engine
	host.mu.Unlock()
	host.epoch.Add(1)
	return nil
}

func (host *EngineHost) Stop(ctx context.Context) error {
	host.opMu.Lock()
	defer host.opMu.Unlock()
	backend, id, err := host.runningBackend()
	if errors.Is(err, engine.ErrNotRunning) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := backend.Stop(ctx); err != nil {
		return err
	}
	host.mu.Lock()
	if host.running == id {
		host.running = ""
	}
	host.mu.Unlock()
	host.epoch.Add(1)
	return nil
}

func (host *EngineHost) Reload(ctx context.Context, prepared engine.PreparedCore) error {
	host.opMu.Lock()
	defer host.opMu.Unlock()
	backend, id, err := host.runningBackend()
	if err != nil {
		return err
	}
	if prepared.Engine != id {
		return fmt.Errorf("%w: cannot reload %q runtime with %q config", engine.ErrUnsupported, id, prepared.Engine)
	}
	if err := backend.Reload(ctx, prepared); err != nil {
		return err
	}
	host.epoch.Add(1)
	return nil
}

func (host *EngineHost) Health(ctx context.Context) (engine.HealthStatus, error) {
	backend, _, err := host.runningBackend()
	if errors.Is(err, engine.ErrNotRunning) {
		return engine.HealthStatus{CheckedAt: time.Now().UTC()}, nil
	}
	if err != nil {
		return engine.HealthStatus{}, err
	}
	return backend.Health(ctx)
}

func (host *EngineHost) Version(ctx context.Context, binary string) (string, error) {
	backend := host.backends[host.selectedEngine()]
	if backend == nil {
		return "", fmt.Errorf("%w: selected engine is not installed", engine.ErrUnsupported)
	}
	return backend.Version(ctx, binary)
}

func (host *EngineHost) Logs() <-chan engine.LogEntry { return host.logs }

func (host *EngineHost) Capabilities() engine.Capabilities {
	if backend, _, err := host.runningBackend(); err == nil {
		return backend.Capabilities()
	}
	if backend := host.backends[host.selectedEngine()]; backend != nil {
		return backend.Capabilities()
	}
	return engine.Capabilities{}
}

func (host *EngineHost) runningBackend() (CoreBackend, string, error) {
	host.mu.RLock()
	id := host.running
	host.mu.RUnlock()
	if id == "" {
		return nil, "", engine.ErrNotRunning
	}
	backend := host.backends[id]
	if backend == nil {
		return nil, id, fmt.Errorf("running engine %q has no backend", id)
	}
	return backend, id, nil
}

func (host *EngineHost) control() (CoreBackend, error) {
	backend, _, err := host.runningBackend()
	return backend, err
}

func (host *EngineHost) Proxies(ctx context.Context) ([]engine.Proxy, error) {
	backend, err := host.control()
	if err != nil {
		return nil, err
	}
	return backend.Proxies(ctx)
}
func (host *EngineHost) Groups(ctx context.Context) ([]engine.ProxyGroup, error) {
	backend, err := host.control()
	if err != nil {
		return nil, err
	}
	return backend.Groups(ctx)
}
func (host *EngineHost) Select(ctx context.Context, group, proxy string) error {
	backend, err := host.control()
	if err != nil {
		return err
	}
	return backend.Select(ctx, group, proxy)
}
func (host *EngineHost) Delay(ctx context.Context, proxy, testURL string, timeout time.Duration) (time.Duration, error) {
	backend, err := host.control()
	if err != nil {
		return 0, err
	}
	return backend.Delay(ctx, proxy, testURL, timeout)
}
func (host *EngineHost) Providers(ctx context.Context, kind engine.ProviderKind) ([]engine.Provider, error) {
	backend, err := host.control()
	if err != nil {
		return nil, err
	}
	return backend.Providers(ctx, kind)
}
func (host *EngineHost) UpdateProvider(ctx context.Context, kind engine.ProviderKind, name string) error {
	backend, err := host.control()
	if err != nil {
		return err
	}
	return backend.UpdateProvider(ctx, kind, name)
}
func (host *EngineHost) Rules(ctx context.Context) ([]engine.Rule, error) {
	backend, err := host.control()
	if err != nil {
		return nil, err
	}
	return backend.Rules(ctx)
}
func (host *EngineHost) Connections(ctx context.Context) (engine.ConnectionsSnapshot, error) {
	backend, err := host.control()
	if err != nil {
		return engine.ConnectionsSnapshot{}, err
	}
	return backend.Connections(ctx)
}
func (host *EngineHost) StreamConnections(ctx context.Context, interval time.Duration) (<-chan engine.ConnectionsSnapshot, error) {
	backend, err := host.control()
	if err != nil {
		return nil, err
	}
	return backend.StreamConnections(ctx, interval)
}
func (host *EngineHost) CloseConnection(ctx context.Context, id string) error {
	backend, err := host.control()
	if err != nil {
		return err
	}
	return backend.CloseConnection(ctx, id)
}
func (host *EngineHost) CloseAllConnections(ctx context.Context) error {
	backend, err := host.control()
	if err != nil {
		return err
	}
	return backend.CloseAllConnections(ctx)
}
func (host *EngineHost) RoutingMode(ctx context.Context) (engine.RoutingMode, error) {
	backend, err := host.control()
	if err != nil {
		return "", err
	}
	return backend.RoutingMode(ctx)
}
func (host *EngineHost) SetRoutingMode(ctx context.Context, mode engine.RoutingMode) error {
	backend, err := host.control()
	if err != nil {
		return err
	}
	return backend.SetRoutingMode(ctx, mode)
}
func (host *EngineHost) StreamTraffic(ctx context.Context) (<-chan engine.TrafficSnapshot, error) {
	backend, err := host.control()
	if err != nil {
		return nil, err
	}
	return backend.StreamTraffic(ctx)
}

var _ CoreBackend = (*EngineHost)(nil)
var _ ActivePreparer = (*EnginePreparer)(nil)
