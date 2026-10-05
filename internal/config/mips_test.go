package config

import (
	"strings"
	"testing"
)

func TestMipsRuntimePatchPreservesUnmanagedValuesForAllTUNModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []MihomoCaptureMode{MihomoCaptureTUN, MihomoCaptureMixed, MihomoCaptureMixed2} {
		t.Run(string(mode), func(t *testing.T) {
			const source = "mode: rule\n# user tuning\ntun:\n  stack: system\n  mtu: 1500\n  congestion-controller: bbr\n  auto-route: true\n"
			result, err := PatchMihomo([]byte(source), MihomoPatch{Capture: &MihomoCapture{Mode: mode, TUNStack: "mips"}})
			if err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{"stack: \"mips\"", "enable: true", "mtu: 1500", "congestion-controller: bbr", "auto-route: false", "# user tuning"} {
				if !strings.Contains(string(result), expected) {
					t.Errorf("runtime missing %q: %s", expected, result)
				}
			}
			managed, err := InspectMihomo(result)
			if err != nil || managed.TUNStack == nil || *managed.TUNStack != "mips" {
				t.Fatalf("managed runtime = %+v, %v", managed, err)
			}
		})
	}
}
