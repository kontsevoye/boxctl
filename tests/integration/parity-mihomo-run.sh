#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
release_manager=
current_manager=
mihomo=
image=
output=
expected_release_sha256=
expected_current_sha256=
expected_release_version=
expected_current_version=
expected_release_commit=
expected_current_commit=

die() { printf 'mihomo-parity: %s\n' "$*" >&2; exit 1; }
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
validate_contract() {
	local contract=$1 label=$2
	jq -e '
		def observed_flow:
			type == "object" and .observed == true and .dataplaneBytesAtLeast1MiB == true and
			(.rule | type == "string") and (.rulePayload | type == "string") and (.chains | type == "array");
		.schema == 1 and .engine == "mihomo" and
		(keys == ["dns","engine","engineContract","proxyProviders","routing","ruleProviders","schema","stimuli"]) and
		.stimuli == {
			fakeDNS:{domain:"fake.parity.integration",originIP:"9.9.9.10",port:5210},
			realDNS:{domain:"real.parity.integration",originIP:"9.9.9.11",port:5211},
			localRule:{domain:"local-rule.parity.integration",originIP:"9.9.9.12",port:5212},
			remoteRule:{domain:"remote-rule.parity.integration",originIP:"9.9.9.13",port:5213},
			localProxy:{originIP:"9.9.9.14",port:5214},remoteProxy:{originIP:"9.9.9.15",port:5215},
			reservedBypass:{originIP:"192.0.2.10",port:5216},reject:{originIP:"9.9.9.16",port:5217}
		} and
		(.engineContract | keys) == ["captureScope","combinedGateway","controllerVersion","dnsmasqUpstream","listeners","nftOwner","policy"] and
		.engineContract.captureScope == "selective-fake-plus-fixture-cidr" and
		.engineContract.combinedGateway == {captureCIDRs:["198.18.0.0/15","9.9.9.0/24"],captureCIDRsConfigured:true,dnsPort:7874,mode:"tproxy",tproxyPort:7894} and
		(.engineContract.controllerVersion | type == "object") and
		.engineContract.listeners == ["tcp:7894","tcp:9090","udp:7874","udp:7894"] and
		.engineContract.nftOwner == "boxctl/v1" and
		.engineContract.policy == {priority:1000,mark:1,table:100,protocol:196,route:"local default dev lo"} and
		.engineContract.dnsmasqUpstream == "127.0.0.1#7874" and
		(.dns | keys) == ["fakeAnswer","fakeFlow","realAnswer","realFlow"] and
		(.dns.fakeAnswer | type == "string" and (startswith("198.18.") or startswith("198.19."))) and
		.dns.realAnswer == "9.9.9.11" and (.dns.fakeFlow | observed_flow) and (.dns.realFlow | observed_flow) and
		(.ruleProviders | keys) == ["local","remote"] and
		.ruleProviders.local.ruleCount == 1 and .ruleProviders.local.vehicleType == "File" and
		.ruleProviders.remote.ruleCount == 1 and .ruleProviders.remote.vehicleType == "HTTP" and
		(.proxyProviders | keys) == ["local","remote"] and
		([.proxyProviders.local,.proxyProviders.remote] | all(.[]; .count == 1 and (.proxies | length) == 1 and .proxies[0].alive == true)) and
		(.routing | keys) == ["fallbackReject","localProxy","localRule","rejectControl","remoteProxy","remoteRule","reservedBypass"] and
		(.routing.localRule | observed_flow) and (.routing.remoteRule | observed_flow) and
		(.routing.localProxy.manager | observed_flow) and (.routing.remoteProxy.manager | observed_flow) and
		.routing.localProxy.upstreamSOCKS5.observed == true and .routing.remoteProxy.upstreamSOCKS5.observed == true and
		.routing.reservedBypass.observed == false and .routing.reservedBypass.liveControllerSnapshotsAtLeast3 == true and .routing.reservedBypass.dataplaneBytesAtLeast1MiB == true and
		.routing.rejectControl.observed == false and .routing.rejectControl.liveControllerSnapshotsAtLeast3 == true and .routing.rejectControl.dataplaneBytesAtLeast1MiB == true and
		.routing.fallbackReject.clientFailed == true and .routing.fallbackReject.originAccepted == false and .routing.fallbackReject.rule.proxy == "REJECT"
	' "$contract" >/dev/null || die "$label observable contract is invalid or incomplete"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--release-manager) [ "$#" -ge 2 ] || die '--release-manager needs a file'; release_manager=$2; shift 2 ;;
		--current-manager) [ "$#" -ge 2 ] || die '--current-manager needs a file'; current_manager=$2; shift 2 ;;
		--mihomo) [ "$#" -ge 2 ] || die '--mihomo needs a file'; mihomo=$2; shift 2 ;;
		--release-sha256) [ "$#" -ge 2 ] || die '--release-sha256 needs a digest'; expected_release_sha256=$2; shift 2 ;;
		--current-sha256) [ "$#" -ge 2 ] || die '--current-sha256 needs a digest'; expected_current_sha256=$2; shift 2 ;;
		--release-version) [ "$#" -ge 2 ] || die '--release-version needs a value'; expected_release_version=$2; shift 2 ;;
		--current-version) [ "$#" -ge 2 ] || die '--current-version needs a value'; expected_current_version=$2; shift 2 ;;
		--release-commit) [ "$#" -ge 2 ] || die '--release-commit needs a value'; expected_release_commit=$2; shift 2 ;;
		--current-commit) [ "$#" -ge 2 ] || die '--current-commit needs a value'; expected_current_commit=$2; shift 2 ;;
		--image) [ "$#" -ge 2 ] || die '--image needs a file'; image=$2; shift 2 ;;
		--output) [ "$#" -ge 2 ] || die '--output needs a directory'; output=$2; shift 2 ;;
		-h|--help)
			printf 'usage: %s --release-manager FILE --release-sha256 HEX --release-version VERSION --release-commit COMMIT --current-manager FILE --current-sha256 HEX --current-version VERSION --current-commit COMMIT --mihomo FILE [--image FILE] --output DIR\n' "$0"
			exit 0
			;;
		*) die "unknown argument: $1" ;;
	esac
done

[ -n "$release_manager" ] || die '--release-manager is required'
[ -n "$current_manager" ] || die '--current-manager is required'
[ -n "$mihomo" ] || die '--mihomo is required'
[ -n "$output" ] || die '--output is required'
[ -n "$expected_release_sha256" ] || die '--release-sha256 is required'
[ -n "$expected_current_sha256" ] || die '--current-sha256 is required'
[ -n "$expected_release_version" ] || die '--release-version is required'
[ -n "$expected_current_version" ] || die '--current-version is required'
[ -n "$expected_release_commit" ] || die '--release-commit is required'
[ -n "$expected_current_commit" ] || die '--current-commit is required'
case "$expected_release_sha256:$expected_current_sha256" in
	*[!0-9a-fA-F:]*|*:*:*|:*) die 'expected manager SHA-256 values are invalid' ;;
esac
[ "${#expected_release_sha256}" -eq 64 ] && [ "${#expected_current_sha256}" -eq 64 ] || \
	die 'expected manager SHA-256 values must contain 64 hexadecimal characters'
sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}
pair_runner_sha256=$(sha256_file "${script_dir}/parity-mihomo-run.sh")
actual_release_sha256=$(sha256_file "$release_manager")
actual_current_sha256=$(sha256_file "$current_manager")
[ "$actual_release_sha256" = "$(printf '%s' "$expected_release_sha256" | tr 'A-F' 'a-f')" ] || \
	die 'release manager SHA-256 does not match --release-sha256'
[ "$actual_current_sha256" = "$(printf '%s' "$expected_current_sha256" | tr 'A-F' 'a-f')" ] || \
	die 'current manager SHA-256 does not match --current-sha256'
[ ! "$release_manager" -ef "$current_manager" ] || die 'release and current manager paths resolve to the same file'
if cmp "$release_manager" "$current_manager" >/dev/null 2>&1; then
	die 'release and current manager artifacts are byte-identical'
fi
[ ! -e "$output" ] || die "output already exists: $output"
mkdir -p "$output"
chmod 700 "$output"
output=$(CDPATH='' cd -- "$output" && pwd -P)

common=(--mihomo "$mihomo" --guest "${script_dir}/guest/parity-mihomo.sh")
if [ -n "$image" ]; then common+=(--image "$image"); fi

"${script_dir}/parity-run-one.sh" \
	--manager "$release_manager" "${common[@]}" --output "${output}/release"
"${script_dir}/parity-run-one.sh" \
	--manager "$current_manager" "${common[@]}" --output "${output}/current"

for variant in release current; do
	for required_file in contract.json semantic-contract.json result.txt manifest.txt versions.txt; do
		[ -f "${output}/${variant}/${required_file}" ] && [ ! -L "${output}/${variant}/${required_file}" ] || \
			die "$variant artifact is missing or unsafe: $required_file"
	done
	for evidence in mihomo_parity_contract=true semantic_contract=true cleanup=true; do
		grep -Fxq "$evidence" "${output}/${variant}/result.txt" || \
			die "$variant result is missing exact evidence: $evidence"
	done
	validate_contract "${output}/${variant}/contract.json" "$variant"
	validate_semantic_contract "${output}/${variant}/semantic-contract.json" "$variant"
	jq -S '.dns.fakeAnswer = "198.18.0.0/15"' "${output}/${variant}/contract.json" \
		>"${output}/${variant}/comparison-contract.json"
done

cmp "${output}/release/semantic-contract.json" "${output}/current/semantic-contract.json" >/dev/null || \
	die 'release/current semantic contracts differ'

[ "$(sed -n 's/^manager_sha256=//p' "${output}/release/manifest.txt")" = "$actual_release_sha256" ] || \
	die 'staged release manager does not match the expected artifact'
[ "$(sed -n 's/^manager_sha256=//p' "${output}/current/manifest.txt")" = "$actual_current_sha256" ] || \
	die 'staged current manager does not match the expected artifact'

for common_key in openwrt_sha256 mihomo_sha256 sing_box_sha256 guest_sha256 scenario_sha256; do
	release_value=$(sed -n "s/^${common_key}=//p" "${output}/release/manifest.txt")
	current_value=$(sed -n "s/^${common_key}=//p" "${output}/current/manifest.txt")
	[ -n "$release_value" ] && [ "$release_value" = "$current_value" ] || \
		die "release/current common input differs: ${common_key}"
done

release_version=$(sed -n '1p' "${output}/release/versions.txt")
current_version=$(sed -n '1p' "${output}/current/versions.txt")
[ -n "$release_version" ] && [ -n "$current_version" ] || die 'manager version evidence is missing'
case "$release_version" in
	"boxctl ${expected_release_version} (commit ${expected_release_commit},"*) ;;
	*) die "release manager version evidence does not match expected version/commit: $release_version" ;;
esac
case "$current_version" in
	"boxctl ${expected_current_version} (commit ${expected_current_commit},"*) ;;
	*) die "current manager version evidence does not match expected version/commit: $current_version" ;;
esac
{
	printf 'release_manager=%s\n' "$release_version"
	printf 'current_manager=%s\n' "$current_version"
	sed 's/^manager_sha256=/release_manager_sha256=/' "${output}/release/manifest.txt" | grep '^release_manager_sha256='
	sed 's/^manager_sha256=/current_manager_sha256=/' "${output}/current/manifest.txt" | grep '^current_manager_sha256='
	printf 'pair_runner_sha256=%s\n' "$pair_runner_sha256"
} >"${output}/artifacts.txt"

if ! cmp "${output}/release/comparison-contract.json" "${output}/current/comparison-contract.json" >/dev/null; then
	diff -u "${output}/release/comparison-contract.json" "${output}/current/comparison-contract.json" \
		>"${output}/contract.diff" || true
	die "observable contracts differ; see ${output}/contract.diff"
fi
cp "${output}/current/contract.json" "${output}/contract.json"
cp "${output}/current/comparison-contract.json" "${output}/comparison-contract.json"
cp "${output}/current/semantic-contract.json" "${output}/semantic-contract.json"
[ "$(sha256_file "${script_dir}/parity-mihomo-run.sh")" = "$pair_runner_sha256" ] || \
	die 'parity-mihomo-run.sh changed while the pair was running'
printf 'release_current_mihomo_parity=true\n' >"${output}/result.txt"
printf 'mihomo-parity: passed; release and current normalized observable contracts are identical: %s\n' "$output"
