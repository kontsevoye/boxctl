package app

import "testing"

func TestProcessStatsCalculatesPerCoreCPUPercent(t *testing.T) {
	t.Parallel()
	service := &StatusService{}
	first := service.processStats(processResourceSnapshot{
		PID: 7, MemoryBytes: 1024, ProcessTicks: 100, SystemTicks: 1000, CPUCount: 2,
	})
	if first == nil || first.MemoryBytes != 1024 || first.CPUPercent != nil {
		t.Fatalf("first sample = %+v", first)
	}
	second := service.processStats(processResourceSnapshot{
		PID: 7, MemoryBytes: 2048, ProcessTicks: 120, SystemTicks: 1200, CPUCount: 2,
	})
	if second == nil || second.MemoryBytes != 2048 || second.CPUPercent == nil || *second.CPUPercent != 20 {
		t.Fatalf("second sample = %+v", second)
	}
}
