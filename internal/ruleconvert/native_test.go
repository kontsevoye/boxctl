package ruleconvert

import (
	"os"
	"testing"
)

func testBinaries(t *testing.T) Binaries {
	t.Helper()
	b := Binaries{SingBox: os.Getenv("BOXCTL_TEST_SING_BOX"), Mihomo: os.Getenv("BOXCTL_TEST_MIHOMO")}
	if b.SingBox == "" || b.Mihomo == "" {
		t.Skip("native codec test requires BOXCTL_TEST_SING_BOX and BOXCTL_TEST_MIHOMO")
	}
	return b
}
