package openwrt_test

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/kontsevoye/boxctl/internal/platform/openwrt"
	"github.com/kontsevoye/boxctl/internal/web"
)

func TestEveryPackagedUCISettingHasPanelAndAPIControls(t *testing.T) {
	config := readProjectFile(t, "packaging/openwrt/files/etc/config/boxctl")
	init := readProjectFile(t, "packaging/openwrt/files/etc/init.d/boxctl")
	panel := readProjectFile(t, "frontend/src/components/ManagementSettingsPanel.tsx")
	translations := readProjectFile(t, "frontend/src/i18n.tsx")
	fields := make(map[string]bool)
	api := reflect.TypeFor[web.ManagementConfig]()
	for index := range api.NumField() {
		fields[api.Field(index).Tag.Get("json")] = true
	}
	var options []string
	for _, match := range regexp.MustCompile(`(?m)^\s*option\s+([a-z_]+)\s`).FindAllStringSubmatch(config, -1) {
		name := match[1]
		options = append(options, name)
		parts := strings.Split(name, "_")
		jsonName := parts[0]
		for _, part := range parts[1:] {
			jsonName += strings.ToUpper(part[:1]) + part[1:]
		}
		if !fields[jsonName] || !strings.Contains(panel, "'"+jsonName+"'") {
			t.Errorf("UCI option %s lacks typed API or panel control", name)
		}
		if strings.Count(translations, "panelSettings_"+jsonName+":") != 2 {
			t.Errorf("UCI option %s needs English and Russian field labels", name)
		}
		if !strings.Contains(init, " main "+name+" ") {
			t.Errorf("UCI option %s lacks init-script wiring", name)
		}
	}
	slices.Sort(options)
	managed := slices.Clone(openwrt.ManagementUCIOptions)
	slices.Sort(managed)
	if !slices.Equal(options, managed) || len(fields) != len(options) {
		t.Fatalf("UCI options %v, adapter options %v, and API fields %v must stay in sync", options, managed, fields)
	}
}
