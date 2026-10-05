package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMihomoMipsUsesNativePreflight(t *testing.T) {
	t.Parallel()
	for _, reject := range []bool{false, true} {
		name := "supported"
		if reject {
			name = "unsupported"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			binary, record, _ := writeFakeMihomo(t, directory)
			source := "mode: rule\ntun:\n  stack: system\n"
			if reject {
				source += "reject-validation: true\n"
			}
			sourcePath := filepath.Join(directory, "config.yaml")
			if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			runtimeBase := t.TempDir()
			prepared, err := NewMihomoDriver(MihomoOptions{}).Prepare(context.Background(), PrepareRequest{
				BinaryPath: binary, SourceConfigPath: sourcePath, RuntimeDir: runtimeBase,
				Capture: CapturePlan{TCP: ProtocolCapture{Method: CaptureTUN}, UDP: ProtocolCapture{Method: CaptureTUN}, TUNDevice: "clash-tun", TUNStack: "mips"},
			})
			if reject {
				if err == nil || !strings.Contains(err.Error(), "requires Mihomo v1.19.31") || !strings.Contains(err.Error(), "native validation rejected config") {
					t.Fatalf("native rejection = %v", err)
				}
				entries, readErr := os.ReadDir(runtimeBase)
				if readErr != nil || len(entries) != 0 {
					t.Fatalf("failed preparation left runtime files: %v, %v", entries, readErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer CleanupPreparedRuntime(prepared)
				content, readErr := os.ReadFile(prepared.RuntimeConfigPath)
				if readErr != nil || prepared.Capture.TUNStack != "mips" || !strings.Contains(string(content), "stack: \"mips\"") {
					t.Fatalf("prepared capture = %+v, config = %s, %v", prepared.Capture, content, readErr)
				}
			}
			args, readErr := os.ReadFile(record)
			if readErr != nil || !strings.Contains(string(args), "-t") {
				t.Fatalf("native validation not executed: %s, %v", args, readErr)
			}
			unchanged, readErr := os.ReadFile(sourcePath)
			if readErr != nil || string(unchanged) != source {
				t.Fatalf("source changed = %s, %v", unchanged, readErr)
			}
		})
	}
}

func TestSingBoxMipsTUNRejectedBeforeCreatingRuntime(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	binary, _ := writeFakeSingBox(t, directory, `{}`)
	sourcePath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(sourcePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeBase := t.TempDir()
	_, err := NewSingBoxDriver(SingBoxOptions{}).Prepare(context.Background(), PrepareRequest{
		BinaryPath: binary, SourceConfigPath: sourcePath, RuntimeDir: runtimeBase,
		Capture: CapturePlan{TCP: ProtocolCapture{Method: CaptureTUN}, UDP: ProtocolCapture{Method: CaptureTUN}, TUNDevice: "sing-box-tun", TUNStack: "mips"},
	})
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "mips requires Mihomo") {
		t.Fatalf("unsupported stack = %v", err)
	}
	entries, readErr := os.ReadDir(runtimeBase)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("rejection created runtime files: %v, %v", entries, readErr)
	}
}
