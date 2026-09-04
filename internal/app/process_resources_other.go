//go:build !linux

package app

func readProcessResourceSnapshot(int) (processResourceSnapshot, error) {
	return processResourceSnapshot{}, errProcessResourcesUnavailable
}
