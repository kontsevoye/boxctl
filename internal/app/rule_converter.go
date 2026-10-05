package app

import (
	"context"
	"os"
	"path/filepath"

	"github.com/kontsevoye/boxctl/internal/ruleconvert"
	"github.com/kontsevoye/boxctl/internal/state"
	"go.yaml.in/yaml/v3"
)

func ruleCodecs(layout state.Layout) func() ruleconvert.Binaries {
	return func() ruleconvert.Binaries {
		singBox, _, _ := resolveSingBoxBinary(layout)
		return ruleconvert.Binaries{SingBox: singBox, Mihomo: filepath.Join(layout.EnginesDir, "mihomo", "mihomo")}
	}
}

type ConvertedRulesService struct {
	Converter *ruleconvert.Service
	Lifecycle *Lifecycle
}

func (s ConvertedRulesService) ConvertedRules(context.Context) ([]ruleconvert.Status, error) {
	snapshot := s.Lifecycle.Snapshot()
	if snapshot.Prepared.RuntimeConfigPath == "" {
		return []ruleconvert.Status{}, nil
	}
	content, err := readBoundedRegular(snapshot.Prepared.RuntimeConfigPath, 32<<20)
	if os.IsNotExist(err) {
		return []ruleconvert.Status{}, nil
	}
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err = yaml.Unmarshal(content, &document); err != nil {
		return nil, err
	}
	return s.Converter.RuntimeStatus(document), nil
}
