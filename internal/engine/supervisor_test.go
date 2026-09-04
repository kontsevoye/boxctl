package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSupervisorAdoptClassifiesKnownOtherEngineStateAsNotOwned(t *testing.T) {
	for _, test := range []struct {
		name   string
		owner  string
		reader string
	}{
		{name: "Mihomo record read by sing-box", owner: mihomoEngineName, reader: SingBoxEngineName},
		{name: "sing-box record read by Mihomo", owner: SingBoxEngineName, reader: mihomoEngineName},
	} {
		t.Run(test.name, func(t *testing.T) {
			statePath := writeSupervisorStateFixture(t, test.owner)
			supervisor := newExternalProcessSupervisor(externalProcessSupervisorOptions{
				Engine: test.reader, ProcessStatePath: statePath,
			})
			if _, err := supervisor.Adopt(context.Background()); !errors.Is(err, ErrProcessStateNotOwned) {
				t.Fatalf("Adopt() error = %v, want ErrProcessStateNotOwned", err)
			}
		})
	}
}

func TestSupervisorAdoptDoesNotIgnoreUnknownEngineState(t *testing.T) {
	statePath := writeSupervisorStateFixture(t, "future-engine")
	supervisor := newExternalProcessSupervisor(externalProcessSupervisorOptions{
		Engine: mihomoEngineName, ProcessStatePath: statePath,
	})
	_, err := supervisor.Adopt(context.Background())
	if err == nil || errors.Is(err, ErrProcessStateNotOwned) {
		t.Fatalf("Adopt() error = %v, want a hard validation failure", err)
	}
}

func writeSupervisorStateFixture(t *testing.T, owner string) string {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "core-process.json")
	persisted := persistedProcess{
		Version:    persistedProcessVersion,
		Engine:     owner,
		PID:        42,
		Identity:   "1234",
		Executable: "/usr/bin/example-core",
		Argv:       []string{"/usr/bin/example-core", "run"},
		StartedAt:  time.Now().UTC(),
		Prepared:   persistedCore{Engine: owner},
	}
	content, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return statePath
}
