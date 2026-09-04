//go:build linux

package app

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readProcessResourceSnapshot(pid int) (processResourceSnapshot, error) {
	processStat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return processResourceSnapshot{}, err
	}
	processTicks, err := parseProcessTicks(string(processStat))
	if err != nil {
		return processResourceSnapshot{}, err
	}
	memoryBytes, err := readResidentMemory(pid)
	if err != nil {
		return processResourceSnapshot{}, err
	}
	systemStat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return processResourceSnapshot{}, err
	}
	systemTicks, cpuCount, err := parseSystemTicks(string(systemStat))
	if err != nil {
		return processResourceSnapshot{}, err
	}
	return processResourceSnapshot{
		PID: pid, MemoryBytes: memoryBytes, ProcessTicks: processTicks,
		SystemTicks: systemTicks, CPUCount: cpuCount,
	}, nil
}

func parseProcessTicks(content string) (uint64, error) {
	closing := strings.LastIndexByte(content, ')')
	if closing < 0 || closing+2 >= len(content) {
		return 0, errProcessResourcesUnavailable
	}
	fields := strings.Fields(content[closing+2:])
	if len(fields) <= 12 {
		return 0, errProcessResourcesUnavailable
	}
	user, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, errProcessResourcesUnavailable
	}
	system, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, errProcessResourcesUnavailable
	}
	return user + system, nil
}

func readResidentMemory(pid int) (uint64, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kibibytes, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr != nil {
				return 0, errProcessResourcesUnavailable
			}
			return kibibytes * 1024, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errProcessResourcesUnavailable
}

func parseSystemTicks(content string) (uint64, int, error) {
	var total uint64
	cpuCount := 0
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "cpu" {
			limit := min(len(fields), 9)
			for _, field := range fields[1:limit] {
				value, err := strconv.ParseUint(field, 10, 64)
				if err != nil {
					return 0, 0, errProcessResourcesUnavailable
				}
				total += value
			}
			continue
		}
		if strings.HasPrefix(fields[0], "cpu") && len(fields[0]) > 3 {
			if _, err := strconv.Atoi(fields[0][3:]); err == nil {
				cpuCount++
			}
		}
	}
	if total == 0 || cpuCount == 0 {
		return 0, 0, errProcessResourcesUnavailable
	}
	return total, cpuCount, nil
}
