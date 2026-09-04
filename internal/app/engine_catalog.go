package app

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontsevoye/boxctl/internal/state"
	updatepkg "github.com/kontsevoye/boxctl/internal/update"
	"github.com/kontsevoye/boxctl/internal/web"
)

var allCaptureModes = []string{"tproxy", "hybrid", "tun", "mixed", "mixed2"}

type EngineCatalogService struct {
	Layout                  state.Layout
	Profiles                state.ProfileStore
	Lifecycle               *Lifecycle
	Host                    *EngineHost
	SingBoxVersion          func(context.Context, string) (string, error)
	UnsafeExternalDashboard bool
}

func (service *EngineCatalogService) Engines(ctx context.Context) ([]web.EngineInfo, error) {
	selected := state.EngineMihomo
	if profile, err := service.Profiles.Current(); err == nil {
		selected = profile.Engine
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	running := ""
	if service.Host != nil {
		running = service.Host.RunningEngine()
	}
	snapshot := LifecycleSnapshot{}
	if service.Lifecycle != nil {
		snapshot = service.Lifecycle.Snapshot()
		if running == "" && snapshot.State == LifecycleRunning {
			running = snapshot.Prepared.Engine
		}
	}
	mihomoPath := filepath.Join(service.Layout.EnginesDir, state.EngineMihomo, "mihomo")
	singPath, singMeta, singErr := resolveSingBoxBinary(service.Layout)
	if singErr != nil && !errors.Is(singErr, fs.ErrNotExist) {
		return nil, singErr
	}
	result := []web.EngineInfo{
		engineInfo(state.EngineMihomo, "Mihomo", "yaml", []string{".yaml", ".yml"}, mihomoPath, "managed", selected, running),
		engineInfo(state.EngineSingBox, "sing-box", "json", []string{".json"}, singPath, singMeta.Source, selected, running),
	}
	if result[1].Installed {
		result[1].Compatible = false
		version := singMeta.Version
		if service.SingBoxVersion != nil {
			if output, versionErr := service.SingBoxVersion(ctx, singPath); versionErr == nil {
				if match := singBoxVersionLine.FindStringSubmatch(output); len(match) == 2 {
					version = match[1]
					result[1].Compatible = true
				}
			}
		} else if singBoxVersionLine.MatchString("sing-box version " + version) {
			result[1].Compatible = true
		}
		result[1].Version = version
	}
	for index := range result {
		result[index].SupportedCaptureModes = append([]string(nil), allCaptureModes...)
		result[index].Management.RemoteProfiles = true
		result[index].Management.Updates = true
		if result[index].ID == state.EngineMihomo {
			result[index].Management.ProxySubscriptions = true
			result[index].Management.LocalRuleLists = true
			result[index].Management.FakeIPCapture = true
			result[index].Management.ExternalDashboard = service.UnsafeExternalDashboard
		}
		if result[index].ID == state.EngineSingBox && result[index].Version == "" && singMeta.Version != "" {
			result[index].Version = singMeta.Version
		}
		if snapshot.State == LifecycleRunning && snapshot.Prepared.Engine == result[index].ID && snapshot.Health.Version != "" {
			result[index].Version = snapshot.Health.Version
		}
	}
	return result, nil
}

func engineInfo(id, display, format string, extensions []string, binary, source, selected, running string) web.EngineInfo {
	installed := regularExecutable(binary)
	if source == "" && installed {
		source = "custom"
	}
	return web.EngineInfo{
		ID: id, DisplayName: display, ConfigFormat: format,
		Extensions: append([]string(nil), extensions...), Installed: installed,
		InstallSource: source, Compatible: installed, Selected: selected == id, Running: running == id,
	}
}

func regularExecutable(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o111 != 0
}

type singBoxCurrent struct {
	Version string `json:"version"`
	Source  string `json:"source"`
	Binary  string `json:"binary"`
}

func resolveSingBoxBinary(layout state.Layout) (string, singBoxCurrent, error) {
	base := filepath.Join(layout.EnginesDir, state.EngineSingBox)
	pointer, err := updatepkg.ReadManagedEnginePointer(base)
	if err == nil {
		resolved, resolveErr := updatepkg.ResolveManagedEngineBinary(base, pointer.Current)
		if resolveErr != nil {
			return "", singBoxCurrent{}, resolveErr
		}
		return resolved, singBoxCurrent{
			Version: pointer.Current.Version, Source: pointer.Current.Source, Binary: pointer.Current.Binary,
		}, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", singBoxCurrent{}, err
	}
	legacy := filepath.Join(base, "sing-box")
	if _, statErr := os.Lstat(legacy); statErr != nil {
		return "", singBoxCurrent{}, statErr
	}
	return legacy, singBoxCurrent{Source: "custom"}, nil
}

var _ web.EngineService = (*EngineCatalogService)(nil)
