package openwrt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const RestartGuardTable = "boxctl_guard"
const RestartGuardMaxLease = 5 * time.Minute
const restartGuardOwner = "boxctl:restart-guard:v1:"

// RestartGuardPlan protects LAN forwarding only. Timed ingress elements make
// the drop rule inert even if the manager is killed without cleanup/restart.
type RestartGuardPlan struct {
	Protected []string `json:"protected"`
	Trusted   []string `json:"trusted"`
}

func (plan RestartGuardPlan) normalized() RestartGuardPlan {
	plan.Protected = normalizeStrings(append([]string(nil), plan.Protected...))
	plan.Trusted = normalizeStrings(append([]string(nil), plan.Trusted...))
	return plan
}

func (plan RestartGuardPlan) validate() error {
	if len(plan.Protected) == 0 || len(plan.Trusted) == 0 {
		return errors.New("openwrt: restart guard requires explicit LAN and trusted local interfaces")
	}
	for _, names := range [][]string{plan.Protected, plan.Trusted} {
		for _, name := range names {
			if !interfaceName.MatchString(name) || name == "lo" {
				return fmt.Errorf("openwrt: invalid restart guard interface %q", name)
			}
		}
	}
	return nil
}

func (plan RestartGuardPlan) comment() string {
	data, _ := json.Marshal(plan.normalized())
	digest := sha256.Sum256(data)
	return restartGuardOwner + hex.EncodeToString(digest[:])
}

// RenderRestartGuard does not install input/output hooks or rely on a list of
// current WAN devices. A new egress is denied by default during the lease.
func RenderRestartGuard(plan RestartGuardPlan, lease time.Duration) (string, error) {
	plan = plan.normalized()
	if err := plan.validate(); err != nil {
		return "", err
	}
	if lease < time.Second || lease > RestartGuardMaxLease {
		return "", errors.New("openwrt: restart guard lease must be between 1 and 300 seconds")
	}
	quote := func(names []string) string {
		values := make([]string, len(names))
		for i, name := range names {
			values[i] = fmt.Sprintf("%q", name)
		}
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf(`table inet %s {
  comment %q
  set protected_lan {
    type ifname
    flags timeout
    timeout %ds
    gc-interval 1s
    elements = { %s }
  }
  set trusted_local {
    type ifname
    elements = { %s }
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname @protected_lan oifname != @trusted_local counter drop
  }
}
`, RestartGuardTable, plan.comment(), int(lease/time.Second), quote(plan.Protected), quote(plan.Trusted)), nil
}

// CheckRestartGuardSupport rejects configured offload and any live flowtable,
// including tables created outside fw4. No router configuration is changed.
func CheckRestartGuardSupport(ctx context.Context, runner Runner) error {
	result, err := runOK(ctx, runner, Command{Name: "uci", Args: []string{"-q", "export", "firewall"}})
	if err != nil {
		return err
	}
	sections, err := parseUCISections(string(result.Stdout))
	if err != nil {
		return err
	}
	for _, section := range sections {
		if section.sectionType != "defaults" {
			continue
		}
		for _, key := range []string{"flow_offloading", "flow_offloading_hw"} {
			for _, value := range section.options[key] {
				switch strings.ToLower(value) {
				case "0", "false", "off", "no":
				default:
					return errors.New("openwrt: restart protection requires software and hardware flow offloading disabled")
				}
			}
		}
	}
	result, err = runOK(ctx, runner, Command{Name: "nft", Args: []string{"-j", "list", "ruleset"}})
	if err != nil {
		return err
	}
	var listing struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(result.Stdout, &listing); err != nil {
		return fmt.Errorf("openwrt: inspect flow offload: %w", err)
	}
	for _, object := range listing.NFTables {
		if _, exists := object["flowtable"]; exists {
			return errors.New("openwrt: restart protection is unavailable while an nftables flowtable exists")
		}
	}
	return nil
}

func inspectRestartGuard(ctx context.Context, runner Runner) (exists bool, comment string, err error) {
	result, err := runner.Run(ctx, Command{Name: "nft", Args: []string{"-j", "list", "table", "inet", RestartGuardTable}})
	if err != nil {
		return false, "", err
	}
	if result.ExitCode != 0 {
		if nftObjectMissing(result.Stderr) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("openwrt: inspect restart guard: %s", strings.TrimSpace(string(result.Stderr)))
	}
	var listing nftListing
	if err := json.Unmarshal(result.Stdout, &listing); err != nil {
		return false, "", err
	}
	for _, object := range listing.NFTables {
		if object.Table == nil || object.Table.Family != "inet" || object.Table.Name != RestartGuardTable {
			continue
		}
		comment := object.Table.Comment
		digest, err := hex.DecodeString(strings.TrimPrefix(comment, restartGuardOwner))
		if !strings.HasPrefix(comment, restartGuardOwner) || err != nil || len(digest) != sha256.Size {
			return true, comment, errors.New("openwrt: refusing to modify foreign inet boxctl_guard table")
		}
		return true, comment, nil
	}
	return false, "", errors.New("openwrt: nft returned no matching restart guard table")
}

// ApplyRestartGuard is serialized by the caller's host-global gateway lock.
// Reapplying the same plan does not renew its kernel timeout.
func ApplyRestartGuard(ctx context.Context, runner Runner, plan RestartGuardPlan, lease time.Duration) error {
	body, err := RenderRestartGuard(plan, lease)
	if err != nil {
		return err
	}
	exists, comment, err := inspectRestartGuard(ctx, runner)
	if err != nil {
		return err
	}
	if exists {
		if comment == plan.comment() {
			return nil
		}
		return errors.New("openwrt: another restart guard plan is already installed")
	}
	if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-c", "-f", "-"}, Stdin: []byte(body)}); err != nil {
		return err
	}
	if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-f", "-"}, Stdin: []byte(body)}); err != nil {
		return err
	}
	exists, comment, err = inspectRestartGuard(ctx, runner)
	if err != nil {
		return err
	}
	if !exists || comment != plan.comment() {
		return errors.New("openwrt: restart guard installation could not be verified")
	}
	return nil
}

func RemoveRestartGuard(ctx context.Context, runner Runner) error {
	exists, _, err := inspectRestartGuard(ctx, runner)
	if err != nil || !exists {
		return err
	}
	body := []byte("delete table inet " + RestartGuardTable + "\n")
	if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-c", "-f", "-"}, Stdin: body}); err != nil {
		return err
	}
	if _, err := runOK(ctx, runner, Command{Name: "nft", Args: []string{"-f", "-"}, Stdin: body}); err != nil {
		return err
	}
	exists, _, err = inspectRestartGuard(ctx, runner)
	if err == nil && exists {
		return errors.New("openwrt: restart guard remains after removal")
	}
	return err
}
