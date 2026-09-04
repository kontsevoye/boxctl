package app

import (
	"errors"
	"math"
	"os"

	"github.com/kontsevoye/boxctl/internal/web"
)

type processResourceSnapshot struct {
	PID          int
	MemoryBytes  uint64
	ProcessTicks uint64
	SystemTicks  uint64
	CPUCount     int
}

type processResourcePrevious struct {
	ProcessTicks uint64
	SystemTicks  uint64
}

func (service *StatusService) collectResources(corePID int, coreRunning bool) *web.ResourceStats {
	read := service.ReadProcessResources
	if read == nil {
		read = readProcessResourceSnapshot
	}
	result := &web.ResourceStats{}
	if current, err := read(os.Getpid()); err == nil {
		result.Manager = service.processStats(current)
	}
	if coreRunning && corePID > 0 {
		if current, err := read(corePID); err == nil {
			result.Core = service.processStats(current)
		}
	}
	if result.Manager == nil && result.Core == nil {
		return nil
	}
	return result
}

func (service *StatusService) processStats(current processResourceSnapshot) *web.ProcessStats {
	if current.PID <= 0 {
		return nil
	}
	result := &web.ProcessStats{MemoryBytes: current.MemoryBytes}
	service.resourcesMu.Lock()
	if service.resourceSamples == nil {
		service.resourceSamples = make(map[int]processResourcePrevious)
	}
	previous, seen := service.resourceSamples[current.PID]
	service.resourceSamples[current.PID] = processResourcePrevious{
		ProcessTicks: current.ProcessTicks,
		SystemTicks:  current.SystemTicks,
	}
	service.resourcesMu.Unlock()
	if !seen || current.ProcessTicks < previous.ProcessTicks || current.SystemTicks <= previous.SystemTicks {
		return result
	}
	processDelta := current.ProcessTicks - previous.ProcessTicks
	systemDelta := current.SystemTicks - previous.SystemTicks
	cpuCount := max(current.CPUCount, 1)
	percent := float64(processDelta) / float64(systemDelta) * float64(cpuCount) * 100
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 {
		return result
	}
	maximum := float64(cpuCount * 100)
	percent = math.Min(percent, maximum)
	percent = math.Round(percent*10) / 10
	result.CPUPercent = &percent
	return result
}

var errProcessResourcesUnavailable = errors.New("process resources are unavailable")
