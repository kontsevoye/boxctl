//go:build linux

package app

import "testing"

func TestParseProcessTicksAllowsSpacesInCommandName(t *testing.T) {
	t.Parallel()
	ticks, err := parseProcessTicks("42 (mihomo worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13")
	if err != nil || ticks != 23 {
		t.Fatalf("parseProcessTicks() = %d, %v", ticks, err)
	}
}

func TestParseSystemTicksCountsCPUs(t *testing.T) {
	t.Parallel()
	ticks, cores, err := parseSystemTicks("cpu  10 20 30 40 50 60 70 80 90 100\ncpu0 1 2 3 4\ncpu1 1 2 3 4\n")
	if err != nil || ticks != 360 || cores != 2 {
		t.Fatalf("parseSystemTicks() = %d, %d, %v", ticks, cores, err)
	}
}
