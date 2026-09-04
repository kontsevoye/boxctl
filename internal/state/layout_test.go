package state

import "testing"

func TestNewLayoutUsesCanonicalBoxctlRootByDefault(t *testing.T) {
	layout, err := NewLayout("")
	if err != nil {
		t.Fatal(err)
	}
	if layout.Root != DefaultRoot || DefaultRoot != "/opt/boxctl" {
		t.Fatalf("default root = %q, want /opt/boxctl", layout.Root)
	}
	if layout.MihomoConfig != "/opt/boxctl/config.yaml" || layout.StateDir != "/opt/boxctl/.boxctl" || layout.DashboardDir != "/opt/boxctl/ui" {
		t.Fatalf("unexpected canonical layout: %#v", layout)
	}
}

func TestNewLayoutRequiresAbsoluteRoot(t *testing.T) {
	if _, err := NewLayout("relative"); err == nil {
		t.Fatal("relative layout root was accepted")
	}
}
