package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"

	"github.com/kontsevoye/boxctl/internal/engine"
	"github.com/kontsevoye/boxctl/internal/fakeip"
	"github.com/kontsevoye/boxctl/internal/web"
)

// FakeIPWhitelistService adapts the marker-aware destination pool to the
// authenticated web API. The compatibility name is retained at the API edge;
// internally this is a firewall capture allowlist, not a DNS allowlist.
type FakeIPWhitelistService struct {
	Manager   *FakeIPCaptureManager
	Preparer  *ActiveMihomoPreparer
	Lifecycle *Lifecycle
}

func (service *FakeIPWhitelistService) FakeIPWhitelist(ctx context.Context) (web.FakeIPWhitelistDocument, error) {
	source, err := service.source(ctx)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, err
	}
	policy, err := service.manager().Inspect(source)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, translateFakeIPServiceError(err)
	}
	return service.webDocument(policy), nil
}

func (service *FakeIPWhitelistService) UpdateFakeIPWhitelist(ctx context.Context, update web.FakeIPWhitelistUpdate) (web.FakeIPWhitelistDocument, error) {
	source, err := service.source(ctx)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, err
	}
	// Validate the selected config before mutating its companion document.
	current, err := service.manager().Inspect(source)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, translateFakeIPServiceError(err)
	}
	if _, err := service.manager().store().SaveManual(update.ManualContent, update.Revision); err != nil {
		return web.FakeIPWhitelistDocument{}, translateFakeIPServiceError(err)
	}
	if current.Applicable {
		if err := service.restartRunning(ctx); err != nil {
			return web.FakeIPWhitelistDocument{}, fmt.Errorf("fake-IP destination pool saved but runtime refresh failed: %w", err)
		}
	}
	policy, err := service.manager().Inspect(source)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, translateFakeIPServiceError(err)
	}
	return service.webDocument(policy), nil
}

func (service *FakeIPWhitelistService) RegenerateFakeIPWhitelist(ctx context.Context, revision string) (web.FakeIPWhitelistDocument, error) {
	source, err := service.source(ctx)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, err
	}
	settings, err := LoadRuntimeSettings(service.Preparer.State)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, fmt.Errorf("load fake-IP generation settings: %w", err)
	}
	if _, err := service.manager().RegenerateWithOptions(source, revision, FakeIPCaptureOptions{
		IncludeExternalIPProviders: settings.AutoFakeIPIncludeExternalIPProviders,
	}); err != nil {
		return web.FakeIPWhitelistDocument{}, translateFakeIPServiceError(err)
	}
	if err := service.restartRunning(ctx); err != nil {
		return web.FakeIPWhitelistDocument{}, fmt.Errorf("fake-IP destination pool regenerated but runtime refresh failed: %w", err)
	}
	// A running restart performs the normal Start/apply AUTO pass. Re-read the
	// final revision rather than returning the pre-restart timestamp/revision.
	policy, err := service.manager().Inspect(source)
	if err != nil {
		return web.FakeIPWhitelistDocument{}, translateFakeIPServiceError(err)
	}
	return service.webDocument(policy), nil
}

func (service *FakeIPWhitelistService) source(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if service == nil || service.Preparer == nil {
		return nil, web.ErrUnavailable
	}
	active, activeErr := service.Preparer.Profiles.Current()
	if activeErr != nil && !errors.Is(activeErr, fs.ErrNotExist) {
		return nil, activeErr
	}
	path, err := service.Preparer.sourcePath(active, activeErr)
	if err != nil {
		return nil, err
	}
	return readBoundedRegular(path, 32<<20)
}

func (service *FakeIPWhitelistService) manager() *FakeIPCaptureManager {
	if service.Manager != nil {
		return service.Manager
	}
	if service.Preparer != nil {
		if service.Preparer.FakeIP != nil {
			return service.Preparer.FakeIP
		}
		return NewFakeIPCaptureManager(service.Preparer.Layout)
	}
	return &FakeIPCaptureManager{}
}

func (service *FakeIPWhitelistService) restartRunning(ctx context.Context) error {
	if service.Lifecycle == nil {
		return nil
	}
	_, err := service.Lifecycle.RestartIfRunning(ctx)
	return err
}

func (service *FakeIPWhitelistService) webDocument(policy fakeIPCapturePolicy) web.FakeIPWhitelistDocument {
	document := web.FakeIPWhitelistDocument{
		ManualContent:  policy.Document.ManualContent,
		GeneratedCIDRs: prefixStrings(policy.Document.Generated),
		FakeIPRanges:   prefixStrings(policy.FakeIPRanges),
		EffectiveCIDRs: prefixStrings(policy.Effective),
		ManualCount:    policy.Document.ManualCount,
		GeneratedCount: policy.Document.GeneratedCount,
		EffectiveCount: len(policy.Effective),
		Revision:       policy.Document.Revision,
		Applicable:     policy.Applicable,
		Selective:      policy.Selective,
		Warnings:       append([]string(nil), policy.Warnings...),
	}
	if !policy.Document.GeneratedAt.IsZero() {
		generatedAt := policy.Document.GeneratedAt.UTC()
		document.GeneratedAt = &generatedAt
	}
	if service.Lifecycle != nil {
		snapshot := service.Lifecycle.Snapshot()
		if snapshot.State == LifecycleRunning {
			document.Applied = captureMatchesFakeIPPolicy(snapshot.Prepared.Capture, policy)
			document.RestartRequired = !document.Applied
		}
	}
	return document
}

func captureMatchesFakeIPPolicy(capture engine.CapturePlan, policy fakeIPCapturePolicy) bool {
	mode := engine.DestinationCaptureAll
	cidrs := []netip.Prefix(nil)
	if policy.Selective {
		mode = engine.DestinationCaptureAllowlist
		cidrs = normalizeNetPrefixes(policy.Effective)
	}
	return capture.Destinations.Mode == mode && slicesEqualPrefixes(capture.Destinations.CIDRs, cidrs)
}

func slicesEqualPrefixes(left, right []netip.Prefix) bool {
	left = normalizeNetPrefixes(left)
	right = normalizeNetPrefixes(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func prefixStrings(prefixes []netip.Prefix) []string {
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.Masked().String()
	}
	return result
}

func translateFakeIPServiceError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, fakeip.ErrConflict):
		return errors.Join(web.ErrConflict, &web.PublicError{Status: http.StatusConflict, Code: "conflict", Message: "Fake-IP destination pool changed; reload and try again"})
	case errors.Is(err, fakeip.ErrInvalidManual), errors.Is(err, fakeip.ErrMalformedMarkers), errors.Is(err, fakeip.ErrTooLarge), errors.Is(err, fakeip.ErrTooManyEntries):
		return &web.PublicError{Status: http.StatusBadRequest, Code: "invalid_fakeip_destinations", Message: "Fake-IP destination pool contains invalid IPv4/CIDR content"}
	case errors.Is(err, errFakeIPModeNotApplicable):
		return &web.PublicError{Status: http.StatusConflict, Code: "fakeip_mode_not_applicable", Message: "Additional fake-IP destinations require whitelist or rule filter mode"}
	default:
		return err
	}
}

var _ web.FakeIPWhitelistService = (*FakeIPWhitelistService)(nil)
