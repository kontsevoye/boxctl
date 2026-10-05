package engine

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/kontsevoye/boxctl/internal/ruleconvert"
	"github.com/kontsevoye/boxctl/internal/state"
	"go.yaml.in/yaml/v3"
)

func prepareConvertedRules(ctx context.Context, service *ruleconvert.Service, codecs func() ruleconvert.Binaries, document map[string]any, prepared PreparedCore) error {
	if service == nil {
		// Existing profiles and isolated driver tests need no converter service.
		raw, _ := yaml.Marshal(document)
		if bytes.Contains(raw, []byte("convert:")) {
			return errors.New("rule converter is unavailable in this operation")
		}
		return nil
	}
	binaries := ruleconvert.Binaries{}
	if codecs != nil {
		binaries = codecs()
	}
	if prepared.Engine == SingBoxEngineName {
		binaries.SingBox = prepared.BinaryPath
	} else {
		binaries.Mihomo = prepared.BinaryPath
	}
	return service.Patch(ctx, document, ruleconvert.ProfileOptions{Target: prepared.Engine, Home: prepared.HomeDir, Binaries: binaries, LoopMark: prepared.Capture.LoopMark})
}
func prepareMihomoConvertedRules(ctx context.Context, service *ruleconvert.Service, codecs func() ruleconvert.Binaries, prepared PreparedCore) error {
	//nolint:gosec // Exact manager-owned private runtime path.
	content, err := os.ReadFile(prepared.RuntimeConfigPath)
	if err != nil {
		return err
	}
	if !bytes.Contains(content, []byte("convert:")) {
		return nil
	}
	var document map[string]any
	if err = yaml.Unmarshal(content, &document); err != nil {
		return err
	}
	if err = prepareConvertedRules(ctx, service, codecs, document, prepared); err != nil {
		return err
	}
	content, err = yaml.Marshal(document)
	if err != nil {
		return err
	}
	return state.WriteFileAtomic(prepared.RuntimeConfigPath, content, 0o600)
}
