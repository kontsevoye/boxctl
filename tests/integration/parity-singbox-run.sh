#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH='' cd -- "${script_dir}/../.." && pwd -P)
manager=
sing_box=
image=
output=
mihomo_result=
expected_manager_sha256=
expected_manager_version=
expected_manager_commit=
mihomo_snapshot=
mihomo_snapshot_manifest=

die() { printf 'singbox-parity: %s\n' "$*" >&2; exit 1; }
sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
manifest_value() {
	local manifest=$1 key=$2 count
	count=$(grep -c "^${key}=" "$manifest" || true)
	[ "$count" -eq 1 ] || die "manifest must contain exactly one ${key}: ${manifest}"
	sed -n "s/^${key}=//p" "$manifest"
}
is_sha256() {
	[ "${#1}" -eq 64 ] || return 1
	case "$1" in *[!0-9a-f]*) return 1 ;; esac
}
validate_semantic_contract() {
	local contract=$1 label=$2
	jq -e '
		.schema == 1 and
		(.common | keys) == ["dataplane","fakeDNS","localProxyPath","localRuleMatched","realDNS","rejectRule","remoteProxyPath","remoteRuleMatched","reservedDirectBypass"] and
		(.common.dataplane | keys) == ["allTransferred","dnsUpstream","listeners","nftOwner","noDirectLeak","policy"] and
		(.common | del(.dataplane) | all(.[]; . == true)) and
		(.common.dataplane | all(.[]; . == true))
	' "$contract" >/dev/null || die "$label semantic contract is invalid or incomplete"
}
build_current_mihomo_scenario_components() {
	local destination=$1 paths_file=$2 staged_path source_path current_openwrt_sha256 mihomo_sha256
	if find "${script_dir}/fixtures" "${script_dir}/guest" "${repo_root}/packaging/openwrt/files" -type l -print -quit | grep -q .; then
		die 'current Mihomo scenario source tree contains a symbolic link'
	fi
	{
		(
			cd "$script_dir"
			find fixtures -type f -print
			find guest -type f ! -path 'guest/run.sh' -print
		)
		printf '%s\n' guest/run.sh host-harness/console.exp host-harness/parity-run-one.sh host-harness/qmp-link-down.py
		(
			cd "$repo_root"
			find packaging/openwrt/files -type f -print | sed 's#^packaging/openwrt/files/#openwrt-files/#'
		)
	} | LC_ALL=C sort >"$paths_file"
	: >"$destination"
	while IFS= read -r staged_path; do
		case "$staged_path" in
			guest/run.sh) source_path="${script_dir}/guest/parity-mihomo.sh" ;;
			fixtures/*|guest/*) source_path="${script_dir}/${staged_path}" ;;
			host-harness/console.exp) source_path="${script_dir}/lib/console.exp" ;;
			host-harness/parity-run-one.sh) source_path="${script_dir}/parity-run-one.sh" ;;
			host-harness/qmp-link-down.py) source_path="${script_dir}/lib/qmp-link-down.py" ;;
			openwrt-files/*) source_path="${repo_root}/packaging/openwrt/files/${staged_path#openwrt-files/}" ;;
			*) die "unexpected current Mihomo scenario path: $staged_path" ;;
		esac
		[ -f "$source_path" ] && [ ! -L "$source_path" ] || \
			die "current Mihomo scenario source is missing or unsafe: $source_path"
		printf '%s  %s\n' "$(sha256_file "$source_path")" "$staged_path" >>"$destination"
	done <"$paths_file"
	mihomo_sha256=$(manifest_value "${mihomo_result}/current/manifest.txt" mihomo_sha256)
	is_sha256 "$mihomo_sha256" || die 'Mihomo core provenance digest is invalid'
	printf '%s  mihomo\n' "$mihomo_sha256" >>"$destination"
	current_openwrt_sha256=$(sed -n 's/^readonly OPENWRT_SHA256="\([0-9a-f]*\)"$/\1/p' "${script_dir}/parity-run-one.sh")
	is_sha256 "$current_openwrt_sha256" || die 'current parity runner OpenWrt digest is invalid'
	printf 'openwrt-image  %s\n' "$current_openwrt_sha256" >>"$destination"
}
cleanup_mihomo_snapshot() {
	[ -z "$mihomo_snapshot" ] || rm -rf "$mihomo_snapshot"
}
verify_mihomo_snapshot() {
	[ "$(sha256_file "$mihomo_snapshot_manifest")" = "$mihomo_snapshot_sha256" ] || \
		die 'Mihomo snapshot manifest changed while sing-box ran'
	while IFS=' ' read -r expected_digest relative_path; do
		[ -n "$expected_digest" ] && [ -n "$relative_path" ] || die 'Mihomo snapshot manifest is malformed'
		[ "$(sha256_file "${mihomo_result}/${relative_path}")" = "$expected_digest" ] || \
			die "Mihomo snapshot changed while sing-box ran: ${relative_path}"
	done <"$mihomo_snapshot_manifest"
}
validate_mihomo_result() {
	grep -Fxq 'release_current_mihomo_parity=true' "${mihomo_result}/result.txt" || \
		die 'Mihomo result does not contain the exact release/current parity claim'
	for variant in release current; do
		jq -e '.schema == 1 and .engine == "mihomo"' "${mihomo_result}/${variant}/contract.json" >/dev/null || \
			die "Mihomo ${variant} contract is invalid"
		for evidence in mihomo_parity_contract=true semantic_contract=true cleanup=true; do
			grep -Fxq "$evidence" "${mihomo_result}/${variant}/result.txt" || \
				die "Mihomo ${variant} result is missing exact evidence: ${evidence}"
		done
		validate_semantic_contract "${mihomo_result}/${variant}/semantic-contract.json" "Mihomo ${variant}"
		jq -S '.dns.fakeAnswer = "198.18.0.0/15"' "${mihomo_result}/${variant}/contract.json" \
			>"${mihomo_result}/${variant}/rederived-comparison-contract.json"
		cmp "${mihomo_result}/${variant}/rederived-comparison-contract.json" \
			"${mihomo_result}/${variant}/comparison-contract.json" >/dev/null || \
			die "Mihomo ${variant} normalized contract was not derived from its raw contract"
	done
	cmp "${mihomo_result}/release/rederived-comparison-contract.json" \
		"${mihomo_result}/current/rederived-comparison-contract.json" >/dev/null || \
		die 'Mihomo release/current normalized contracts no longer compare equal'
	cmp "${mihomo_result}/release/semantic-contract.json" "${mihomo_result}/current/semantic-contract.json" >/dev/null || \
		die 'Mihomo release/current semantic contracts differ'
	cmp "${mihomo_result}/semantic-contract.json" "${mihomo_result}/current/semantic-contract.json" >/dev/null || \
		die 'Mihomo root semantic contract does not match its current-manager contract'
	cmp "${mihomo_result}/contract.json" "${mihomo_result}/current/contract.json" >/dev/null || \
		die 'Mihomo root contract does not match its current-manager contract'
	cmp "${mihomo_result}/comparison-contract.json" "${mihomo_result}/current/rederived-comparison-contract.json" >/dev/null || \
		die 'Mihomo root normalized contract does not match its current-manager contract'
	for common_key in openwrt_sha256 mihomo_sha256 sing_box_sha256 guest_sha256 scenario_sha256; do
		release_value=$(manifest_value "${mihomo_result}/release/manifest.txt" "$common_key")
		current_value=$(manifest_value "${mihomo_result}/current/manifest.txt" "$common_key")
		[ -n "$release_value" ] && [ "$release_value" = "$current_value" ] || \
			die "Mihomo release/current common input differs: ${common_key}"
	done
	cmp "${mihomo_result}/release/scenario-components.txt" "${mihomo_result}/current/scenario-components.txt" >/dev/null || \
		die 'Mihomo release/current scenario component manifests differ'
	for variant in release current; do
		[ "$(sha256_file "${mihomo_result}/${variant}/scenario-components.txt")" = \
			"$(manifest_value "${mihomo_result}/${variant}/manifest.txt" scenario_sha256)" ] || \
			die "Mihomo ${variant} scenario digest does not match its component manifest"
	done
	current_scenario_components="${mihomo_result}/current-source-scenario-components.txt"
	build_current_mihomo_scenario_components "$current_scenario_components" "${mihomo_result}/current-source-scenario-paths.txt"
	cmp "$current_scenario_components" "${mihomo_result}/current/scenario-components.txt" >/dev/null || \
		die 'Mihomo result was produced by stale scenario sources or host harness'
	[ "$(manifest_value "${mihomo_result}/current/manifest.txt" guest_sha256)" = \
		"$(sha256_file "${script_dir}/guest/parity-mihomo.sh")" ] || die 'Mihomo guest digest is stale'
	current_runner_openwrt_sha256=$(sed -n 's/^readonly OPENWRT_SHA256="\([0-9a-f]*\)"$/\1/p' "${script_dir}/parity-run-one.sh")
	[ "$(manifest_value "${mihomo_result}/current/manifest.txt" openwrt_sha256)" = "$current_runner_openwrt_sha256" ] || \
		die 'Mihomo OpenWrt digest differs from the current parity runner'
	mihomo_release_manager_sha256=$(manifest_value "${mihomo_result}/release/manifest.txt" manager_sha256)
	mihomo_current_manager_sha256=$(manifest_value "${mihomo_result}/current/manifest.txt" manager_sha256)
	mihomo_release_manager_version=$(sed -n '1p' "${mihomo_result}/release/versions.txt")
	mihomo_current_manager_version=$(sed -n '1p' "${mihomo_result}/current/versions.txt")
	[ -n "$mihomo_release_manager_version" ] && [ -n "$mihomo_current_manager_version" ] || \
		die 'Mihomo manager version evidence is empty'
	if [ "$(manifest_value "${mihomo_result}/artifacts.txt" release_manager)" != "$mihomo_release_manager_version" ] || \
		[ "$(manifest_value "${mihomo_result}/artifacts.txt" current_manager)" != "$mihomo_current_manager_version" ]; then
		die 'Mihomo root manager version evidence differs from per-run versions'
	fi
	if [ "$(manifest_value "${mihomo_result}/artifacts.txt" release_manager_sha256)" != "$mihomo_release_manager_sha256" ] || \
		[ "$(manifest_value "${mihomo_result}/artifacts.txt" current_manager_sha256)" != "$mihomo_current_manager_sha256" ]; then
		die 'Mihomo root manager digests differ from per-run manifests'
	fi
	mihomo_pair_runner_sha256=$(manifest_value "${mihomo_result}/artifacts.txt" pair_runner_sha256)
	is_sha256 "$mihomo_pair_runner_sha256" || die 'Mihomo pair runner provenance digest is invalid'
	[ "$mihomo_pair_runner_sha256" = "$(sha256_file "${script_dir}/parity-mihomo-run.sh")" ] || \
		die 'Mihomo result was produced by a stale pair runner'
	case "${mihomo_release_manager_sha256}:${mihomo_current_manager_sha256}" in
		*[!0-9a-f:]*|*:*:*|:*) die 'Mihomo manager provenance digests are invalid' ;;
	esac
	[ "${#mihomo_release_manager_sha256}" -eq 64 ] && [ "${#mihomo_current_manager_sha256}" -eq 64 ] || \
		die 'Mihomo manager provenance digests must contain 64 hexadecimal characters'
	[ "$mihomo_release_manager_sha256" != "$mihomo_current_manager_sha256" ] || \
		die 'Mihomo release/current manager artifacts are not distinct'
	[ "$mihomo_current_manager_sha256" = "$actual_manager_sha256" ] || \
		die 'Mihomo current-manager digest differs from the manager used for sing-box'
	mihomo_openwrt_sha256=$(manifest_value "${mihomo_result}/current/manifest.txt" openwrt_sha256)
	mihomo_scenario_sha256=$(manifest_value "${mihomo_result}/current/manifest.txt" scenario_sha256)
	if ! is_sha256 "$mihomo_openwrt_sha256" || ! is_sha256 "$mihomo_scenario_sha256"; then
		die 'Mihomo OpenWrt/scenario provenance digests are invalid'
	fi
	mihomo_contract_sha256=$(sha256_file "${mihomo_result}/contract.json")
}
snapshot_mihomo_result() {
	local mihomo_result_source temporary_root relative_path
	local -a required_paths=(
		result.txt artifacts.txt contract.json comparison-contract.json semantic-contract.json
		release/result.txt release/contract.json release/comparison-contract.json release/semantic-contract.json release/manifest.txt release/versions.txt release/scenario-components.txt
		current/result.txt current/contract.json current/comparison-contract.json current/semantic-contract.json current/manifest.txt current/versions.txt current/scenario-components.txt
	)
	[ -d "$mihomo_result" ] || die '--mihomo-result is not a directory'
	mihomo_result_source=$(CDPATH='' cd -- "$mihomo_result" && pwd -P)
	temporary_root=${TMPDIR:-/tmp}
	[ -d "$temporary_root" ] || die "temporary directory does not exist: $temporary_root"
	mihomo_snapshot=$(mktemp -d "${temporary_root%/}/boxctl-mihomo-result.XXXXXX")
	mkdir -p "$mihomo_snapshot/release" "$mihomo_snapshot/current"
	for relative_path in "${required_paths[@]}"; do
		[ -f "${mihomo_result_source}/${relative_path}" ] && [ ! -L "${mihomo_result_source}/${relative_path}" ] || \
			die "Mihomo result artifact is missing or unsafe: ${relative_path}"
		install -m 0600 "${mihomo_result_source}/${relative_path}" "${mihomo_snapshot}/${relative_path}"
	done
	mihomo_result=$mihomo_snapshot
	mihomo_snapshot_manifest="${mihomo_snapshot}/snapshot-manifest.txt"
	: >"$mihomo_snapshot_manifest"
	for relative_path in "${required_paths[@]}"; do
		printf '%s %s\n' "$(sha256_file "${mihomo_result}/${relative_path}")" "$relative_path" >>"$mihomo_snapshot_manifest"
	done
	mihomo_snapshot_sha256=$(sha256_file "$mihomo_snapshot_manifest")
	validate_mihomo_result
}

trap cleanup_mihomo_snapshot EXIT HUP INT TERM

while [ "$#" -gt 0 ]; do
	case "$1" in
		--manager) [ "$#" -ge 2 ] || die '--manager needs a file'; manager=$2; shift 2 ;;
		--sing-box) [ "$#" -ge 2 ] || die '--sing-box needs a file'; sing_box=$2; shift 2 ;;
		--mihomo-result) [ "$#" -ge 2 ] || die '--mihomo-result needs a directory'; mihomo_result=$2; shift 2 ;;
		--manager-sha256) [ "$#" -ge 2 ] || die '--manager-sha256 needs a digest'; expected_manager_sha256=$2; shift 2 ;;
		--manager-version) [ "$#" -ge 2 ] || die '--manager-version needs a value'; expected_manager_version=$2; shift 2 ;;
		--manager-commit) [ "$#" -ge 2 ] || die '--manager-commit needs a value'; expected_manager_commit=$2; shift 2 ;;
		--image) [ "$#" -ge 2 ] || die '--image needs a file'; image=$2; shift 2 ;;
		--output) [ "$#" -ge 2 ] || die '--output needs a directory'; output=$2; shift 2 ;;
		-h|--help)
			printf 'usage: %s --manager FILE --manager-sha256 HEX --manager-version VERSION --manager-commit COMMIT --sing-box FILE [--mihomo-result DIR] [--image FILE] --output DIR\n' "$0"
			exit 0
			;;
		*) die "unknown argument: $1" ;;
	esac
done

[ -n "$manager" ] || die '--manager is required'
[ -n "$sing_box" ] || die '--sing-box is required'
[ -n "$output" ] || die '--output is required'
[ -n "$expected_manager_sha256" ] || die '--manager-sha256 is required'
[ -n "$expected_manager_version" ] || die '--manager-version is required'
[ -n "$expected_manager_commit" ] || die '--manager-commit is required'
case "$expected_manager_sha256" in *[!0-9a-fA-F]*|'') die 'manager SHA-256 is invalid' ;; esac
[ "${#expected_manager_sha256}" -eq 64 ] || die 'manager SHA-256 must contain 64 hexadecimal characters'
actual_manager_sha256=$(sha256_file "$manager")
[ "$actual_manager_sha256" = "$(printf '%s' "$expected_manager_sha256" | tr 'A-F' 'a-f')" ] || die 'manager SHA-256 does not match'
actual_sing_box_sha256=$(sha256_file "$sing_box")
sing_runner_sha256=$(sha256_file "${script_dir}/parity-singbox-run.sh")
[ ! -e "$output" ] || die "output already exists: $output"
[ -z "$mihomo_result" ] || snapshot_mihomo_result

arguments=(--manager "$manager" --sing-box "$sing_box" --guest "${script_dir}/guest/parity-singbox.sh" --output "$output")
if [ -n "$image" ]; then arguments+=(--image "$image"); fi
"${script_dir}/parity-run-one.sh" "${arguments[@]}"
[ -z "$mihomo_result" ] || verify_mihomo_snapshot

jq -e '.schema == 1 and .engine == "sing-box"' "${output}/contract.json" >/dev/null || die 'sing-box contract is invalid'
validate_semantic_contract "${output}/semantic-contract.json" sing-box
for evidence in singbox_parity_contract=true semantic_contract=true cleanup=true; do
	grep -Fxq "$evidence" "${output}/result.txt" || die "sing-box result is missing exact evidence: ${evidence}"
done
[ "$(manifest_value "${output}/manifest.txt" manager_sha256)" = "$actual_manager_sha256" ] || die 'staged manager digest changed'
[ "$(manifest_value "${output}/manifest.txt" sing_box_sha256)" = "$actual_sing_box_sha256" ] || die 'staged sing-box digest changed'
sing_openwrt_sha256=$(manifest_value "${output}/manifest.txt" openwrt_sha256)
sing_scenario_sha256=$(manifest_value "${output}/manifest.txt" scenario_sha256)
if ! is_sha256 "$sing_openwrt_sha256" || ! is_sha256 "$sing_scenario_sha256"; then
	die 'sing-box OpenWrt/scenario provenance digests are invalid'
fi
manager_version=$(sed -n '1p' "${output}/versions.txt")
case "$manager_version" in
	"boxctl ${expected_manager_version} (commit ${expected_manager_commit},"*) ;;
	*) die "manager version evidence differs: $manager_version" ;;
esac
{
	printf 'manager=%s\n' "$manager_version"
	printf 'manager_sha256=%s\n' "$actual_manager_sha256"
	printf 'sing_box_sha256=%s\n' "$actual_sing_box_sha256"
	printf 'openwrt_sha256=%s\n' "$sing_openwrt_sha256"
	printf 'sing_scenario_sha256=%s\n' "$sing_scenario_sha256"
	printf 'sing_runner_sha256=%s\n' "$sing_runner_sha256"
} >"${output}/artifacts.txt"

if [ -n "$mihomo_result" ]; then
	[ "$mihomo_openwrt_sha256" = "$sing_openwrt_sha256" ] || \
		die 'Mihomo and sing-box runs used different OpenWrt images'
	jq -e -n --slurpfile mihomo "${mihomo_result}/contract.json" --slurpfile sing "${output}/contract.json" \
		'$mihomo[0].stimuli == $sing[0].stimuli' >/dev/null || die 'Mihomo and sing-box stimuli differ'
	{
		printf 'mihomo_contract_sha256=%s\n' "$mihomo_contract_sha256"
		printf 'mihomo_snapshot_sha256=%s\n' "$mihomo_snapshot_sha256"
		printf 'mihomo_release_manager=%s\n' "$mihomo_release_manager_version"
		printf 'mihomo_current_manager=%s\n' "$mihomo_current_manager_version"
		printf 'mihomo_release_manager_sha256=%s\n' "$mihomo_release_manager_sha256"
		printf 'mihomo_current_manager_sha256=%s\n' "$mihomo_current_manager_sha256"
		printf 'mihomo_scenario_sha256=%s\n' "$mihomo_scenario_sha256"
		printf 'mihomo_pair_runner_sha256=%s\n' "$mihomo_pair_runner_sha256"
	} >>"${output}/artifacts.txt"
	jq -S -n \
		--arg mihomo_contract_sha256 "$mihomo_contract_sha256" \
		--arg mihomo_snapshot_sha256 "$mihomo_snapshot_sha256" \
		--arg mihomo_release_manager "$mihomo_release_manager_version" \
		--arg mihomo_current_manager "$mihomo_current_manager_version" \
		--arg mihomo_release_manager_sha256 "$mihomo_release_manager_sha256" \
		--arg mihomo_current_manager_sha256 "$mihomo_current_manager_sha256" \
		--arg mihomo_scenario_sha256 "$mihomo_scenario_sha256" \
		--arg mihomo_pair_runner_sha256 "$mihomo_pair_runner_sha256" \
		--arg sing_manager_sha256 "$actual_manager_sha256" \
		--arg sing_scenario_sha256 "$sing_scenario_sha256" \
		--arg sing_runner_sha256 "$sing_runner_sha256" \
		--arg openwrt_sha256 "$sing_openwrt_sha256" \
		--slurpfile mihomo "${mihomo_result}/contract.json" --slurpfile sing "${output}/contract.json" '
		def pass($name; $m; $s): {invariant:$name,mihomo:$m,singBox:$s,match:($m == $s and $m == true)};
		def has_chain($flow; $chain): (($flow.chains // []) | index($chain)) != null;
		def controller($flow): $flow | {rule,rulePayload,chains};
		{
			schema:1,
			comparison:"semantic",
			stimuli:$sing[0].stimuli,
			stimuliEqual:($mihomo[0].stimuli == $sing[0].stimuli),
			provenance:{
				mihomoContractSHA256:$mihomo_contract_sha256,
				mihomoSnapshotSHA256:$mihomo_snapshot_sha256,
				mihomoReleaseManager:$mihomo_release_manager,
				mihomoCurrentManager:$mihomo_current_manager,
				mihomoReleaseManagerSHA256:$mihomo_release_manager_sha256,
				mihomoCurrentManagerSHA256:$mihomo_current_manager_sha256,
				singBoxCurrentManagerSHA256:$sing_manager_sha256,
				mihomoScenarioSHA256:$mihomo_scenario_sha256,
				mihomoPairRunnerSHA256:$mihomo_pair_runner_sha256,
				singBoxScenarioSHA256:$sing_scenario_sha256,
				singBoxRunnerSHA256:$sing_runner_sha256,
				openwrtSHA256:$openwrt_sha256,
				currentManagerAligned:($mihomo_current_manager_sha256 == $sing_manager_sha256),
				releaseCurrentManagersDistinct:($mihomo_release_manager_sha256 != $mihomo_current_manager_sha256)
			},
			controllerEvidence:{
				fakeDNS:{mihomo:controller($mihomo[0].dns.fakeFlow),singBox:controller($sing[0].dns.fakeFlow)},
				realDNS:{mihomo:controller($mihomo[0].dns.realFlow),singBox:controller($sing[0].dns.realFlow)},
				localRule:{mihomo:controller($mihomo[0].routing.localRule),singBox:controller($sing[0].routing.localRule)},
				remoteRule:{mihomo:controller($mihomo[0].routing.remoteRule),singBox:controller($sing[0].routing.remoteRule)},
				localProxy:{mihomo:controller($mihomo[0].routing.localProxy.manager),singBox:controller($sing[0].routing.localProxy.manager)},
				remoteProxy:{mihomo:controller($mihomo[0].routing.remoteProxy.manager),singBox:controller($sing[0].routing.remoteProxy.manager)}
			},
			providerEvidence:{mihomo:$mihomo[0].proxyProviders,singBox:$sing[0].proxyProviders},
			ruleSetEvidence:{mihomo:$mihomo[0].ruleProviders,singBox:$sing[0].ruleProviders},
			rows:[
				pass("fake DNS answer is in 198.18/15"; ($mihomo[0].dns.fakeAnswer | startswith("198.18.") or startswith("198.19.")); ($sing[0].dns.fakeAnswer | startswith("198.18.") or startswith("198.19."))),
				pass("real DNS answer is exact"; ($mihomo[0].dns.realAnswer == "9.9.9.11"); ($sing[0].dns.realAnswer == "9.9.9.11")),
				pass("fake DNS flow was captured and transferred"; ($mihomo[0].dns.fakeFlow.observed and $mihomo[0].dns.fakeFlow.dataplaneBytesAtLeast1MiB); ($sing[0].dns.fakeFlow.observed and $sing[0].dns.fakeFlow.dataplaneBytesAtLeast1MiB)),
				pass("real DNS flow was captured and transferred"; ($mihomo[0].dns.realFlow.observed and $mihomo[0].dns.realFlow.dataplaneBytesAtLeast1MiB); ($sing[0].dns.realFlow.observed and $sing[0].dns.realFlow.dataplaneBytesAtLeast1MiB)),
				pass("local native rule matched live traffic and controller details";
					($mihomo[0].routing.localRule.observed and $mihomo[0].routing.localRule.dataplaneBytesAtLeast1MiB and (($mihomo[0].routing.localRule.rule | ascii_downcase) == "ruleset") and $mihomo[0].routing.localRule.rulePayload == "parity-local-rules" and has_chain($mihomo[0].routing.localRule; "DIRECT"));
					($sing[0].routing.localRule.observed and $sing[0].routing.localRule.dataplaneBytesAtLeast1MiB and ($sing[0].routing.localRule.rule | contains("rule_set=parity-local-rules") and contains("route(parity-direct)")) and $sing[0].routing.localRule.rulePayload == "" and has_chain($sing[0].routing.localRule; "parity-direct"))),
				pass("remote native rule matched live traffic and controller details";
					($mihomo[0].routing.remoteRule.observed and $mihomo[0].routing.remoteRule.dataplaneBytesAtLeast1MiB and (($mihomo[0].routing.remoteRule.rule | ascii_downcase) == "ruleset") and $mihomo[0].routing.remoteRule.rulePayload == "parity-remote-rules" and has_chain($mihomo[0].routing.remoteRule; "DIRECT"));
					($sing[0].routing.remoteRule.observed and $sing[0].routing.remoteRule.dataplaneBytesAtLeast1MiB and ($sing[0].routing.remoteRule.rule | contains("rule_set=parity-remote-rules") and contains("route(parity-direct)")) and $sing[0].routing.remoteRule.rulePayload == "" and has_chain($sing[0].routing.remoteRule; "parity-direct"))),
				pass("local proxy path reached hermetic upstream and controller chain";
					($mihomo[0].routing.localProxy.manager.observed and $mihomo[0].routing.localProxy.manager.dataplaneBytesAtLeast1MiB and $mihomo[0].routing.localProxy.manager.rulePayload == "9.9.9.14/32" and has_chain($mihomo[0].routing.localProxy.manager; "PARITY-LOCAL-PROXY") and has_chain($mihomo[0].routing.localProxy.manager; "parity-local-node") and $mihomo[0].routing.localProxy.upstreamSOCKS5.observed);
					($sing[0].routing.localProxy.manager.observed and $sing[0].routing.localProxy.manager.dataplaneBytesAtLeast1MiB and ($sing[0].routing.localProxy.manager.rule | contains("ip_cidr=9.9.9.14/32") and contains("route(parity-local-selector)")) and $sing[0].routing.localProxy.manager.rulePayload == "" and has_chain($sing[0].routing.localProxy.manager; "parity-local-proxy") and has_chain($sing[0].routing.localProxy.manager; "parity-local-selector") and $sing[0].routing.localProxy.upstreamSOCKS5.observed)),
				pass("remote proxy equivalent reached hermetic upstream and controller chain";
					($mihomo[0].routing.remoteProxy.manager.observed and $mihomo[0].routing.remoteProxy.manager.dataplaneBytesAtLeast1MiB and $mihomo[0].routing.remoteProxy.manager.rulePayload == "9.9.9.15/32" and has_chain($mihomo[0].routing.remoteProxy.manager; "PARITY-REMOTE-PROXY") and has_chain($mihomo[0].routing.remoteProxy.manager; "parity-remote-node") and $mihomo[0].routing.remoteProxy.upstreamSOCKS5.observed);
					($sing[0].routing.remoteProxy.manager.observed and $sing[0].routing.remoteProxy.manager.dataplaneBytesAtLeast1MiB and ($sing[0].routing.remoteProxy.manager.rule | contains("ip_cidr=9.9.9.15/32") and contains("route(parity-remote-profile-selector)")) and $sing[0].routing.remoteProxy.manager.rulePayload == "" and has_chain($sing[0].routing.remoteProxy.manager; "parity-remote-profile-proxy") and has_chain($sing[0].routing.remoteProxy.manager; "parity-remote-profile-selector") and $sing[0].routing.remoteProxy.upstreamSOCKS5.observed)),
				pass("local rule set is materialized"; ($mihomo[0].ruleProviders.local.ruleCount == 1 and $mihomo[0].ruleProviders.local.vehicleType == "File"); ($sing[0].ruleProviders.local.ruleCount == 1 and $sing[0].ruleProviders.local.vehicleType == "File" and $sing[0].ruleProviders.local.native == true)),
				pass("remote rule set is materialized"; ($mihomo[0].ruleProviders.remote.ruleCount == 1 and $mihomo[0].ruleProviders.remote.vehicleType == "HTTP"); ($sing[0].ruleProviders.remote.ruleCount == 1 and $sing[0].ruleProviders.remote.vehicleType == "HTTP" and $sing[0].ruleProviders.remote.native == true)),
				pass("local proxy resource is available";
					($mihomo[0].proxyProviders.local.count == 1 and $mihomo[0].proxyProviders.local.count == ($mihomo[0].proxyProviders.local.proxies | length) and $mihomo[0].proxyProviders.local.name == "parity-local-proxies" and $mihomo[0].proxyProviders.local.proxies[0] == {name:"parity-local-node",type:"Socks5",alive:true});
					($sing[0].proxyProviders.local.count == 1 and $sing[0].proxyProviders.local.count == ($sing[0].proxyProviders.local.proxies | length) and $sing[0].proxyProviders.local.name == "parity-local-proxy" and $sing[0].proxyProviders.local.proxies[0] == {name:"parity-local-proxy",type:"Socks",alive:true})),
				pass("remote proxy resource is available";
					($mihomo[0].proxyProviders.remote.count == 1 and $mihomo[0].proxyProviders.remote.count == ($mihomo[0].proxyProviders.remote.proxies | length) and $mihomo[0].proxyProviders.remote.name == "parity-remote-proxies" and $mihomo[0].proxyProviders.remote.proxies[0] == {name:"parity-remote-node",type:"Socks5",alive:true});
					($sing[0].proxyProviders.remote.count == 1 and $sing[0].proxyProviders.remote.count == ($sing[0].proxyProviders.remote.proxies | length) and $sing[0].proxyProviders.remote.name == "ParityRemote" and $sing[0].proxyProviders.remote.proxies[0] == {name:"parity-remote-profile-proxy",type:"Socks",alive:true})),
				pass("native dynamic proxy-provider capability is accurately different"; ($mihomo[0].proxyProviders.remote.vehicleType == "HTTP"); ($sing[0].proxyProviders.remote.dynamicSupported == false and $sing[0].proxyProviders.remote.apiUnsupported == true)),
				pass("reserved destination bypassed core"; ($mihomo[0].routing.reservedBypass.observed == false and $mihomo[0].routing.reservedBypass.dataplaneBytesAtLeast1MiB); ($sing[0].routing.reservedBypass.observed == false and $sing[0].routing.reservedBypass.dataplaneBytesAtLeast1MiB)),
				pass("same-target reject control succeeded outside core"; ($mihomo[0].routing.rejectControl.observed == false and $mihomo[0].routing.rejectControl.dataplaneBytesAtLeast1MiB); ($sing[0].routing.rejectControl.observed == false and $sing[0].routing.rejectControl.dataplaneBytesAtLeast1MiB)),
				pass("reject rule blocked origin"; ($mihomo[0].routing.fallbackReject.clientFailed and $mihomo[0].routing.fallbackReject.originAccepted == false and $mihomo[0].routing.fallbackReject.rule.proxy == "REJECT"); ($sing[0].routing.rejectRule.clientExit != 0 and $sing[0].routing.rejectRule.nativeRulePresent and $sing[0].routing.rejectRule.originAccepted == false)),
				pass("owned nft/policy/DNS dataplane present";
					($mihomo[0].engineContract.nftOwner == "boxctl/v1" and
					 $mihomo[0].engineContract.policy == {priority:1000,mark:1,table:100,protocol:196,route:"local default dev lo"} and
					 $mihomo[0].engineContract.dnsmasqUpstream == "127.0.0.1#7874" and
					 $mihomo[0].engineContract.listeners == ["tcp:7894","tcp:9090","udp:7874","udp:7894"]);
					($sing[0].engineContract.nftOwner == "boxctl/v1" and
					 $sing[0].engineContract.policy == {priority:1000,mark:1,table:100,protocol:196,route:"local default dev lo"} and
					 $sing[0].engineContract.dnsmasqUpstream == "127.0.0.1#7874" and
					 $sing[0].engineContract.listeners == ["tcp:7894","tcp:9090","udp:7874","udp:7894"])
				)
			],
			expectedDifferences:{
				captureScope:{mihomo:($mihomo[0].engineContract.captureScope // "selective-fixture-ranges"),singBox:"broad"},
				nativeDynamicProxyProvider:{mihomo:true,singBox:$sing[0].proxyProviders.remote.dynamicSupported},
				remoteProxyMechanism:{mihomo:$mihomo[0].proxyProviders.remote.vehicleType,singBox:$sing[0].proxyProviders.remote.vehicleType},
				nativeRulePayloadField:{mihomo:"typed-payload",singBox:($sing[0].routing.localRule.rulePayload // "")}
			}
		}
	' >"${output}/cross-engine-matrix.json"
	jq -e '
		.stimuliEqual == true and .provenance.currentManagerAligned == true and
		.provenance.releaseCurrentManagersDistinct == true and all(.rows[]; .match == true)
	' "${output}/cross-engine-matrix.json" >/dev/null || die 'cross-engine semantic invariant mismatch'
fi

[ "$(sha256_file "${script_dir}/parity-singbox-run.sh")" = "$sing_runner_sha256" ] || \
	die 'parity-singbox-run.sh changed while the scenario was running'
printf 'current_singbox_parity=true\ncross_engine_matrix=%s\n' "$([ -n "$mihomo_result" ] && printf true || printf not-requested)" \
	>"${output}/runner-result.txt"
printf 'singbox-parity: passed: %s\n' "$output"
