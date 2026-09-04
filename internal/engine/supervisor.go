package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kontsevoye/boxctl/internal/state"
)

const (
	persistedProcessVersion = 2
	maxProcessStateSize     = 4 << 20
	defaultStopTimeout      = 10 * time.Second
	defaultLogBuffer        = 512
)

type processLogPump func(context.Context, PreparedCore, func(string, string))

type externalProcessSupervisorOptions struct {
	Engine           string
	DisplayName      string
	ProcessStatePath string
	StopTimeout      time.Duration
	LogBuffer        int
	DefaultArgs      func(PreparedCore) []string
	Validate         func(context.Context, PreparedCore) error
	ValidatePrepared func(PreparedCore) error
	Cleanup          func(PreparedCore)
	LogPump          processLogPump
}

// externalProcessSupervisor contains the process-group, handoff, logging and
// cleanup behavior shared by all external cores. Engine drivers retain native
// validation, controller and capability policy.
type externalProcessSupervisor struct {
	engine           string
	displayName      string
	processStatePath string
	stopTimeout      time.Duration
	logs             chan LogEntry
	defaultArgs      func(PreparedCore) []string
	validate         func(context.Context, PreparedCore) error
	validatePrepared func(PreparedCore) error
	cleanup          func(PreparedCore)
	logPump          processLogPump
	sequence         atomic.Uint64

	mu              sync.RWMutex
	cmd             *exec.Cmd
	pid             int
	processIdentity string
	executable      string
	argv            []string
	done            chan struct{}
	prepared        PreparedCore
	startedAt       time.Time
	lastExitError   string
	logCancel       context.CancelFunc
}

func newExternalProcessSupervisor(options externalProcessSupervisorOptions) *externalProcessSupervisor {
	stopTimeout := options.StopTimeout
	if stopTimeout <= 0 {
		stopTimeout = defaultStopTimeout
	}
	logBuffer := options.LogBuffer
	if logBuffer <= 0 {
		logBuffer = defaultLogBuffer
	}
	displayName := strings.TrimSpace(options.DisplayName)
	if displayName == "" {
		displayName = options.Engine
	}
	return &externalProcessSupervisor{
		engine:           options.Engine,
		displayName:      displayName,
		processStatePath: options.ProcessStatePath,
		stopTimeout:      stopTimeout,
		logs:             make(chan LogEntry, logBuffer),
		defaultArgs:      options.DefaultArgs,
		validate:         options.Validate,
		validatePrepared: options.ValidatePrepared,
		cleanup:          options.Cleanup,
		logPump:          options.LogPump,
	}
}

type persistedCore struct {
	Engine            string             `json:"engine"`
	BinaryPath        string             `json:"binaryPath"`
	SourceConfigPath  string             `json:"sourceConfigPath"`
	SourceRevision    string             `json:"sourceRevision,omitempty"`
	RuntimeConfigPath string             `json:"runtimeConfigPath"`
	RuntimeConfigRoot string             `json:"runtimeConfigRoot"`
	HomeDir           string             `json:"homeDir"`
	Args              []string           `json:"args"`
	Env               []string           `json:"env,omitempty"`
	Capture           CapturePlan        `json:"capture"`
	Controller        ControllerEndpoint `json:"controller"`
	Capabilities      Capabilities       `json:"capabilities"`
}

type persistedProcess struct {
	Version    int           `json:"version"`
	Engine     string        `json:"engine"`
	PID        int           `json:"pid"`
	Identity   string        `json:"identity"`
	Executable string        `json:"executable"`
	Argv       []string      `json:"argv"`
	StartedAt  time.Time     `json:"startedAt"`
	Prepared   persistedCore `json:"prepared"`
}

// Version 1 was Mihomo-only. Keep this decoder permanently: an old manager may
// be replaced while its core process is still alive.
type legacyMihomoPrepared struct {
	Engine            string             `json:"engine"`
	BinaryPath        string             `json:"binaryPath"`
	SourceConfigPath  string             `json:"sourceConfigPath"`
	SourceRevision    string             `json:"sourceRevision,omitempty"`
	RuntimeConfigPath string             `json:"runtimeConfigPath"`
	RuntimeConfigRoot string             `json:"runtimeConfigRoot"`
	HomeDir           string             `json:"homeDir"`
	Args              []string           `json:"args"`
	Env               []string           `json:"env,omitempty"`
	Capture           CapturePlan        `json:"capture"`
	Controller        ControllerEndpoint `json:"controller"`
	Capabilities      Capabilities       `json:"capabilities"`
}

type legacyMihomoProcess struct {
	Version    int                  `json:"version"`
	PID        int                  `json:"pid"`
	Identity   string               `json:"identity"`
	StartedAt  time.Time            `json:"startedAt"`
	LaunchArgs []string             `json:"launchArgs"`
	Prepared   legacyMihomoPrepared `json:"prepared"`
}

func persistPreparedCore(prepared PreparedCore) persistedCore {
	return persistedCore{
		Engine: prepared.Engine, BinaryPath: prepared.BinaryPath,
		SourceConfigPath: prepared.SourceConfigPath, SourceRevision: prepared.SourceRevision, RuntimeConfigPath: prepared.RuntimeConfigPath,
		RuntimeConfigRoot: prepared.runtimeConfigRoot, HomeDir: prepared.HomeDir,
		Args: append([]string(nil), prepared.Args...), Env: append([]string(nil), prepared.Env...),
		Capture: cloneCapturePlan(prepared.Capture), Controller: prepared.Controller, Capabilities: prepared.Capabilities,
	}
}

func (persisted persistedCore) preparedCore() PreparedCore {
	return PreparedCore{
		Engine: persisted.Engine, BinaryPath: persisted.BinaryPath,
		SourceConfigPath: persisted.SourceConfigPath, SourceRevision: persisted.SourceRevision, RuntimeConfigPath: persisted.RuntimeConfigPath,
		HomeDir: persisted.HomeDir, Args: append([]string(nil), persisted.Args...), Env: append([]string(nil), persisted.Env...),
		Capture: cloneCapturePlan(persisted.Capture), Controller: persisted.Controller, Capabilities: persisted.Capabilities,
		runtimeConfigRoot: persisted.RuntimeConfigRoot, runtimeConfigOwnedPath: persisted.RuntimeConfigPath,
	}
}

func (persisted legacyMihomoPrepared) preparedCore() PreparedCore {
	engine := persisted.Engine
	if engine == "" {
		engine = mihomoEngineName
	}
	return persistedCore{
		Engine: engine, BinaryPath: persisted.BinaryPath,
		SourceConfigPath: persisted.SourceConfigPath, SourceRevision: persisted.SourceRevision, RuntimeConfigPath: persisted.RuntimeConfigPath,
		RuntimeConfigRoot: persisted.RuntimeConfigRoot, HomeDir: persisted.HomeDir,
		Args: persisted.Args, Env: persisted.Env, Capture: persisted.Capture,
		Controller: persisted.Controller, Capabilities: persisted.Capabilities,
	}.preparedCore()
}

func cloneCapturePlan(capture CapturePlan) CapturePlan {
	capture.FakeIPRanges = append([]netip.Prefix(nil), capture.FakeIPRanges...)
	capture.Destinations.CIDRs = append([]netip.Prefix(nil), capture.Destinations.CIDRs...)
	capture.EndpointBypassCIDRs = append([]netip.Prefix(nil), capture.EndpointBypassCIDRs...)
	capture.TUNAddresses = append([]netip.Prefix(nil), capture.TUNAddresses...)
	return capture
}

func clonePreparedCore(prepared PreparedCore) PreparedCore {
	prepared.Args = append([]string(nil), prepared.Args...)
	prepared.Env = append([]string(nil), prepared.Env...)
	prepared.Capture = cloneCapturePlan(prepared.Capture)
	return prepared
}

//nolint:staticcheck // Darwin handoff stubs always fail; Linux uses the returned identity and error dynamically.
func (s *externalProcessSupervisor) Start(ctx context.Context, prepared PreparedCore) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.validate == nil {
		return errors.New("engine supervisor has no native validator")
	}
	if err := s.validate(ctx, prepared); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	if s.pid != 0 {
		s.mu.Unlock()
		return ErrAlreadyRunning
	}
	args := append([]string(nil), prepared.Args...)
	if len(args) == 0 && s.defaultArgs != nil {
		args = append([]string(nil), s.defaultArgs(prepared)...)
	}
	//nolint:gosec // each engine verifies an explicit regular executable before supervision
	cmd := exec.Command(prepared.BinaryPath, args...)
	cmd.Dir = prepared.HomeDir
	cmd.Env = append(os.Environ(), prepared.Env...)
	cmd.SysProcAttr = childProcessAttributes(s.processStatePath != "")
	var stdout, stderr *lineLogWriter
	if s.processStatePath == "" {
		stdout = &lineLogWriter{emit: s.emitLog, stream: "stdout"}
		stderr = &lineLogWriter{emit: s.emitLog, stream: "stderr"}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
	} else {
		// Stable service descriptors let the child survive manager replacement.
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	process, err := startChildProcess(cmd)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("start %s: %w", s.displayName, err)
	}
	done := make(chan struct{})
	s.cmd = cmd
	s.pid = cmd.Process.Pid
	s.done = done
	s.prepared = clonePreparedCore(prepared)
	s.startedAt = time.Now().UTC()
	s.lastExitError = ""
	if s.processStatePath != "" {
		identity, executable, argv, identityErr := captureProcessExecution(cmd.Process.Pid)
		if identityErr != nil {
			s.clearRunningLocked()
			s.mu.Unlock()
			_ = signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
			_ = process.Wait()
			return fmt.Errorf("identify %s process: %w", s.displayName, identityErr)
		}
		s.processIdentity = identity
		s.executable = executable
		s.argv = append([]string(nil), argv...)
		if stateErr := s.writeProcessStateLocked(prepared); stateErr != nil {
			s.clearRunningLocked()
			s.mu.Unlock()
			_ = signalProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
			_ = process.Wait()
			s.removeProcessState()
			return stateErr
		}
	}
	s.mu.Unlock()

	s.emitLog("supervisor", fmt.Sprintf("%s started with pid %d", s.displayName, cmd.Process.Pid))
	go s.waitProcess(cmd, process, done, stdout, stderr)
	if s.processStatePath != "" {
		s.startLogPump(prepared)
	}
	return nil
}

func (s *externalProcessSupervisor) waitProcess(cmd *exec.Cmd, process *startedProcess, done chan struct{}, stdout, stderr *lineLogWriter) {
	err := process.Wait()
	if stdout != nil {
		stdout.Flush()
	}
	if stderr != nil {
		stderr.Flush()
	}
	var finished PreparedCore
	s.mu.Lock()
	if s.cmd == cmd {
		finished = s.prepared
		s.clearRunningLocked()
		if err != nil {
			s.lastExitError = err.Error()
		}
	}
	s.mu.Unlock()
	s.removeProcessState()
	s.cleanupPrepared(finished)
	close(done)
	if err != nil {
		s.emitLog("supervisor", s.displayName+" exited: "+err.Error())
	} else {
		s.emitLog("supervisor", s.displayName+" exited")
	}
}

func (s *externalProcessSupervisor) Stop(ctx context.Context) error {
	s.mu.RLock()
	pid := s.pid
	identity := s.processIdentity
	executable := s.executable
	argv := append([]string(nil), s.argv...)
	done := s.done
	prepared := clonePreparedCore(s.prepared)
	s.mu.RUnlock()
	if pid == 0 {
		return nil
	}
	waitExited := func() bool {
		if done != nil {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}
		return !persistedProcessAlive(pid, identity)
	}
	finishAdopted := func() {
		if done != nil {
			return
		}
		s.mu.Lock()
		if s.pid == pid && s.processIdentity == identity {
			s.clearRunningLocked()
		}
		s.mu.Unlock()
		s.removeProcessState()
		s.cleanupPrepared(prepared)
	}
	waitNoLongerOwned := func() error {
		if done == nil {
			finishAdopted()
			return nil
		}
		timer := time.NewTimer(s.stopTimeout)
		defer timer.Stop()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("%s process identity changed but the original child was not reaped", s.displayName)
		}
	}
	signalOwned := func(signal syscall.Signal) (bool, error) {
		return signalVerifiedProcessGroup(pid, identity, executable, argv, prepared.BinaryPath, signal)
	}

	owned, err := signalOwned(syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("verify and terminate %s process group: %w", s.displayName, err)
	}
	if !owned {
		return waitNoLongerOwned()
	}
	timer := time.NewTimer(s.stopTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	killed := false
	for {
		if waitExited() {
			finishAdopted()
			return nil
		}
		select {
		case <-ctx.Done():
			owned, killErr := signalOwned(syscall.SIGKILL)
			if !owned {
				return ctx.Err()
			}
			return errors.Join(ctx.Err(), wrapProcessSignalError(s.displayName, "kill", killErr))
		case <-timer.C:
			if killed {
				return fmt.Errorf("%s process did not exit after SIGKILL", s.displayName)
			}
			s.emitLog("supervisor", s.displayName+" did not stop after SIGTERM; sending SIGKILL")
			owned, err = signalOwned(syscall.SIGKILL)
			if err != nil {
				return fmt.Errorf("kill %s process group: %w", s.displayName, err)
			}
			if !owned {
				return waitNoLongerOwned()
			}
			killed = true
			timer.Reset(2 * time.Second)
		case <-ticker.C:
		}
	}
}

// signalVerifiedProcessGroup revalidates the kernel-observed execution record
// immediately before every signal. A stale PID/PGID must never make boxctl
// signal an unrelated process after manager handoff or delayed cleanup.
//
//nolint:staticcheck // Darwin never has a persisted identity; Linux evaluates the validator dynamically.
func signalVerifiedProcessGroup(pid int, identity, executable string, argv []string, binary string, signal syscall.Signal) (bool, error) {
	if identity != "" {
		if err := validatePersistedProcessExecution(pid, identity, executable, argv, binary); err != nil {
			if !persistedProcessAlive(pid, identity) {
				return false, nil
			}
			return false, fmt.Errorf("refusing to signal a changed process: %w", err)
		}
	}
	if err := signalProcessGroup(pid, signal); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return false, nil
		}
		return true, err
	}
	return true, nil
}

func wrapProcessSignalError(displayName, operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %s process group: %w", operation, displayName, err)
}

//nolint:staticcheck // Darwin handoff stubs always fail; Linux validates live state dynamically.
func (s *externalProcessSupervisor) Adopt(ctx context.Context) (PreparedCore, error) {
	if err := ctx.Err(); err != nil {
		return PreparedCore{}, err
	}
	persisted, legacy, legacyArgs, err := s.readProcessState()
	if err != nil {
		return PreparedCore{}, err
	}
	prepared := persisted.Prepared.preparedCore()
	if s.validatePrepared == nil {
		return PreparedCore{}, errors.New("engine supervisor has no prepared-state validator")
	}
	if err := s.validatePrepared(prepared); err != nil {
		return PreparedCore{}, err
	}
	if legacy {
		if err := validatePersistedProcess(persisted.PID, persisted.Identity, prepared.BinaryPath, legacyArgs); err != nil {
			return PreparedCore{}, err
		}
		identity, executable, argv, captureErr := captureProcessExecution(persisted.PID)
		if captureErr != nil {
			return PreparedCore{}, captureErr
		}
		persisted.Identity, persisted.Executable, persisted.Argv = identity, executable, argv
	} else if err := validatePersistedProcessExecution(persisted.PID, persisted.Identity, persisted.Executable, persisted.Argv, prepared.BinaryPath); err != nil {
		return PreparedCore{}, err
	}

	s.mu.Lock()
	if s.pid != 0 {
		s.mu.Unlock()
		return PreparedCore{}, ErrAlreadyRunning
	}
	s.pid = persisted.PID
	s.processIdentity = persisted.Identity
	s.executable = persisted.Executable
	s.argv = append([]string(nil), persisted.Argv...)
	s.prepared = clonePreparedCore(prepared)
	s.startedAt = persisted.StartedAt
	s.lastExitError = ""
	if legacy {
		if err := s.writeProcessStateLocked(prepared); err != nil {
			s.clearRunningLocked()
			s.mu.Unlock()
			return PreparedCore{}, fmt.Errorf("upgrade legacy Mihomo process state: %w", err)
		}
	}
	s.mu.Unlock()

	s.emitLog("supervisor", fmt.Sprintf("%s process %d adopted from the previous boxctl manager", s.displayName, persisted.PID))
	s.startLogPump(prepared)
	go s.reapAdoptedChild(persisted.PID, persisted.Identity, prepared)
	return prepared, nil
}

func (s *externalProcessSupervisor) reapAdoptedChild(pid int, identity string, prepared PreparedCore) {
	reaped, err := waitAdoptedChild(pid)
	if err != nil {
		s.emitLog("supervisor", "could not wait for adopted "+s.displayName+" process: "+err.Error())
		return
	}
	if !reaped {
		return
	}
	s.mu.Lock()
	if s.pid != pid || s.processIdentity != identity {
		s.mu.Unlock()
		return
	}
	s.clearRunningLocked()
	s.lastExitError = "adopted " + s.displayName + " process exited"
	s.mu.Unlock()
	s.removeProcessState()
	s.cleanupPrepared(prepared)
	s.emitLog("supervisor", "adopted "+s.displayName+" process exited")
}

func (s *externalProcessSupervisor) replacePrepared(prepared PreparedCore) (PreparedCore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pid == 0 {
		return PreparedCore{}, ErrNotRunning
	}
	previous := clonePreparedCore(s.prepared)
	// The native reload has already succeeded when this method is called, so
	// in-memory supervision must follow the running process even if persistence
	// fails. This preserves the previous Mihomo driver's failure semantics.
	s.prepared = clonePreparedCore(prepared)
	if err := s.writeProcessStateValues(s.pid, s.processIdentity, s.executable, s.argv, s.startedAt, prepared); err != nil {
		return previous, err
	}
	return previous, nil
}

func (s *externalProcessSupervisor) snapshot() (int, string, PreparedCore, time.Time, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pid, s.processIdentity, clonePreparedCore(s.prepared), s.startedAt, s.lastExitError
}

func (s *externalProcessSupervisor) ActiveControllerEndpoint() (ControllerEndpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pid == 0 {
		return ControllerEndpoint{}, ErrNotRunning
	}
	return s.prepared.Controller, nil
}

func (s *externalProcessSupervisor) Logs() <-chan LogEntry { return s.logs }

func (s *externalProcessSupervisor) emitLog(stream, message string) {
	entry := LogEntry{Sequence: s.sequence.Add(1), Time: time.Now().UTC(), Stream: stream, Message: message}
	select {
	case s.logs <- entry:
	default:
	}
}

func (s *externalProcessSupervisor) startLogPump(prepared PreparedCore) {
	if s.logPump == nil {
		return
	}
	s.mu.Lock()
	if s.logCancel != nil {
		s.logCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.logCancel = cancel
	s.mu.Unlock()
	go s.logPump(ctx, clonePreparedCore(prepared), s.emitLog)
}

func (s *externalProcessSupervisor) clearRunningLocked() {
	s.cmd = nil
	s.pid = 0
	s.processIdentity = ""
	s.executable = ""
	s.argv = nil
	s.done = nil
	s.prepared = PreparedCore{}
	if s.logCancel != nil {
		s.logCancel()
		s.logCancel = nil
	}
}

func (s *externalProcessSupervisor) cleanupPrepared(prepared PreparedCore) {
	if s.cleanup != nil && prepared.RuntimeConfigPath != "" {
		s.cleanup(prepared)
	}
}

func (s *externalProcessSupervisor) writeProcessStateLocked(prepared PreparedCore) error {
	return s.writeProcessStateValues(s.pid, s.processIdentity, s.executable, s.argv, s.startedAt, prepared)
}

func (s *externalProcessSupervisor) writeProcessStateValues(pid int, identity, executable string, argv []string, startedAt time.Time, prepared PreparedCore) error {
	if s.processStatePath == "" {
		return nil
	}
	persistedPrepared := persistPreparedCore(prepared)
	// Version 1 callers could construct a Mihomo PreparedCore without setting
	// Engine because validatePreparedMihomo historically accepted the zero
	// value. Preserve that launch compatibility while making v2 state explicit.
	if persistedPrepared.Engine == "" && s.engine == mihomoEngineName {
		persistedPrepared.Engine = mihomoEngineName
	}
	persisted := persistedProcess{
		Version: persistedProcessVersion, Engine: s.engine, PID: pid, Identity: identity,
		Executable: executable, Argv: append([]string(nil), argv...), StartedAt: startedAt,
		Prepared: persistedPrepared,
	}
	if err := validatePersistedState(persisted, s.engine); err != nil {
		return err
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s process state: %w", s.displayName, err)
	}
	data = append(data, '\n')
	if err := state.WriteFileAtomic(s.processStatePath, data, 0o600); err != nil {
		return fmt.Errorf("persist %s process state: %w", s.displayName, err)
	}
	return nil
}

func (s *externalProcessSupervisor) readProcessState() (persistedProcess, bool, []string, error) {
	if s.processStatePath == "" {
		return persistedProcess{}, false, nil, os.ErrNotExist
	}
	info, err := os.Lstat(s.processStatePath)
	if err != nil {
		return persistedProcess{}, false, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxProcessStateSize {
		return persistedProcess{}, false, nil, fmt.Errorf("%s process state is not a private regular file", s.displayName)
	}
	content, err := os.ReadFile(s.processStatePath)
	if err != nil {
		return persistedProcess{}, false, nil, err
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(content, &header); err != nil {
		return persistedProcess{}, false, nil, fmt.Errorf("decode %s process state header: %w", s.displayName, err)
	}
	switch header.Version {
	case persistedProcessVersion:
		var persisted persistedProcess
		if err := decodeStrictJSON(content, &persisted); err != nil {
			return persistedProcess{}, false, nil, fmt.Errorf("decode %s process state: %w", s.displayName, err)
		}
		if err := validatePersistedState(persisted, s.engine); err != nil {
			return persistedProcess{}, false, nil, err
		}
		return persisted, false, nil, nil
	case 1:
		if s.engine != mihomoEngineName {
			return persistedProcess{}, false, nil, fmt.Errorf("%w: legacy process state belongs to Mihomo", ErrProcessStateNotOwned)
		}
		var legacy legacyMihomoProcess
		if err := decodeStrictJSON(content, &legacy); err != nil {
			return persistedProcess{}, false, nil, fmt.Errorf("decode legacy Mihomo process state: %w", err)
		}
		if legacy.PID <= 1 || legacy.Identity == "" || legacy.StartedAt.IsZero() {
			return persistedProcess{}, false, nil, errors.New("legacy Mihomo process state is invalid")
		}
		prepared := legacy.Prepared.preparedCore()
		return persistedProcess{
			Version: persistedProcessVersion, Engine: mihomoEngineName, PID: legacy.PID,
			Identity: legacy.Identity, StartedAt: legacy.StartedAt, Prepared: persistPreparedCore(prepared),
		}, true, append([]string(nil), legacy.LaunchArgs...), nil
	default:
		return persistedProcess{}, false, nil, fmt.Errorf("unsupported %s process state version %d", s.displayName, header.Version)
	}
}

func validatePersistedState(persisted persistedProcess, expectedEngine string) error {
	if persisted.Version != persistedProcessVersion || persisted.Engine == "" ||
		persisted.PID <= 1 || persisted.Identity == "" || persisted.Executable == "" || len(persisted.Argv) == 0 || persisted.StartedAt.IsZero() {
		return fmt.Errorf("%s process state is invalid", expectedEngine)
	}
	if persisted.Engine != expectedEngine {
		switch persisted.Engine {
		case mihomoEngineName, SingBoxEngineName:
			return fmt.Errorf("%w: process state belongs to %q, not %q", ErrProcessStateNotOwned, persisted.Engine, expectedEngine)
		default:
			return fmt.Errorf("%s process state is invalid", expectedEngine)
		}
	}
	if persisted.Prepared.Engine != expectedEngine {
		return fmt.Errorf("process state engine %q does not match prepared engine %q", persisted.Engine, persisted.Prepared.Engine)
	}
	return nil
}

func decodeStrictJSON(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func (s *externalProcessSupervisor) removeProcessState() {
	if s.processStatePath == "" {
		return
	}
	if info, err := os.Lstat(s.processStatePath); err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		_ = os.Remove(s.processStatePath)
	}
}

func signalProcessGroup(pid int, signal syscall.Signal) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to signal unsafe process group %d", pid)
	}
	return syscall.Kill(-pid, signal)
}

type lineLogWriter struct {
	emit   func(string, string)
	stream string
	mu     sync.Mutex
	buffer []byte
}

func (w *lineLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buffer = append(w.buffer, data...)
	for {
		index := bytes.IndexByte(w.buffer, '\n')
		if index < 0 {
			break
		}
		line := strings.TrimSuffix(string(w.buffer[:index]), "\r")
		w.buffer = w.buffer[index+1:]
		w.emit(w.stream, line)
	}
	if len(w.buffer) > maxCommandOutput {
		w.emit(w.stream, string(w.buffer[:maxCommandOutput])+"…")
		w.buffer = w.buffer[:0]
	}
	return len(data), nil
}

func (w *lineLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buffer) == 0 {
		return
	}
	w.emit(w.stream, strings.TrimSuffix(string(w.buffer), "\r"))
	w.buffer = nil
}

func runtimeFileOwnedBy(prepared PreparedCore, prefix, extension string) bool {
	path := filepath.Clean(prepared.RuntimeConfigPath)
	root := filepath.Clean(prepared.runtimeConfigRoot)
	ownedPath := filepath.Clean(prepared.runtimeConfigOwnedPath)
	return path != "." && root != "." && ownedPath != "." && path == ownedPath &&
		path != filepath.Clean(prepared.SourceConfigPath) && filepath.Dir(path) == root &&
		strings.HasPrefix(filepath.Base(path), prefix) && filepath.Ext(path) == extension
}

var _ io.Writer = (*lineLogWriter)(nil)
