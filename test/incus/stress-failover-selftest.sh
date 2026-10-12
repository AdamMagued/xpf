#!/usr/bin/env bash
# Hermetic RG1-owner and iperf-log regression cells for #12199.
# No Incus, cluster, network, or live log access: all external calls are mocked.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STRESS_OWNER_TIMEOUT=2
STRESS_OWNER_INTERVAL=1
# shellcheck source=test/incus/stress-failover-lib.sh
source "${SCRIPT_DIR}/stress-failover-lib.sh"

PASS=0
FAIL=0
ERRORS=()
SELFTEST_PASS=0
SELFTEST_FAIL=0

info() { printf 'INFO: %s\n' "$*"; }
pass() { printf '  PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); ERRORS+=("$*"); }
ok() { printf 'PASS: %s\n' "$*"; SELFTEST_PASS=$((SELFTEST_PASS + 1)); }
bad() { printf 'FAIL: %s\n' "$*" >&2; SELFTEST_FAIL=$((SELFTEST_FAIL + 1)); }

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
export MOCK_STATUS_CALLS="${TMP_DIR}/status-calls"
: > "$MOCK_STATUS_CALLS"
FW0=fw0
FW1=fw1
CLUSTER_LAN_HOST=lan
# shellcheck disable=SC2034  # consumed by stress-failover-lib.sh
IPERF_STREAMS=8
# shellcheck disable=SC2034  # consumed by stress-failover-lib.sh
LOG=/tmp/fixture-iperf.log
MOCK_STATUS_MODE=steady
MOCK_LOG_MODE=empty
MOCK_REQUEST_MODE=success

# FormatStatus-shaped fixture: status query output on fw0 starts with node0,
# output on fw1 starts with node1. Include Transfer-ready, Manual, secondary-
# hold and optional locally-overridden peer-state annotations from the renderer.
mock_status() {
	local rg1_owner="$1" local_node="$2" rg0_owner="${3:-node0}"
	local hold="${4:-no}" annotate="${5:-no}"
	local rg node0_state node1_state node0_render node1_render
	local node0_manual takeover
	for rg in 0 1 2; do
		if [[ "$rg" == 1 ]]; then
			if [[ "$rg1_owner" == node0 ]]; then node0_state=primary; node1_state=secondary
			else node0_state=secondary; node1_state=primary; fi
			if [[ "$hold" == yes ]]; then node0_state=secondary-hold; fi
		elif [[ "$rg0_owner" == node0 ]]; then
			node0_state=primary; node1_state=secondary
		else
			node0_state=secondary; node1_state=primary
		fi
		node0_render="$node0_state"
		node1_render="$node1_state"
		if [[ "$annotate" == yes && "$local_node" == node0 && "$rg" == 1 ]]; then
			node1_render+=' (local: transfer-out override)'
		elif [[ "$annotate" == yes && "$local_node" == node1 && "$rg" == 1 ]]; then
			node0_render+=' (local: transfer-out override)'
		fi
		node0_manual=no
		if [[ "$rg" == 1 && "$hold" == yes && "$local_node" == node0 ]]; then
			node0_manual=yes
		fi
		if [[ "$local_node" == node0 ]]; then takeover=no
		else takeover=yes; fi
		printf 'Redundancy group: %s , Failover count: 0\n' "$rg"
		if [[ "$local_node" == node0 ]]; then
			printf 'node0   200       %-14s no       %-4s     None\n' "$node0_render" "$node0_manual"
			printf '  Takeover ready: %s\n' "$takeover"
			printf '  Transfer ready: yes\n'
			printf 'node1   100       %-14s no       no       None\n' "$node1_render"
		else
			printf 'node1   100       %-14s no       no       None\n' "$node1_render"
			printf '  Takeover ready: %s\n' "$takeover"
			printf '  Transfer ready: yes\n'
			printf 'node0   200       %-14s no       no       None\n' "$node0_render"
		fi
		printf '\n'
	done
}

mock_log() {
	local streams="${1:-8}" mode="${2:-healthy}" rate i
	for ((i = 1; i <= streams; i++)); do
		rate='8.00 Gbits/sec'
		if [[ "$mode" == dead && $i -eq 3 ]]; then rate='0.00 bits/sec'; fi
		printf '[  %d] 0.00-1.00 sec 1.00 GBytes %s\n' "$i" "$rate"
	done
	printf '[SUM] 0.00-1.00 sec 8.00 GBytes 8.00 Gbits/sec\n'
}

# File-backed status-call indexing survives the command substitutions in the
# poller. The default mock is an unchanged node0 owner, which must FAIL a
# node1-expected poll rather than manufacture a successful move.
incus() {
	local args="$*" node call_count owner
	[[ "$1" == exec ]] || { printf 'unexpected incus call: %s\n' "$args" >&2; return 90; }
	shift
	node="$1"
	if [[ "$args" == *'show chassis cluster status'* ]]; then
		printf '%s\n' "$node" >> "$MOCK_STATUS_CALLS"
		call_count=$(wc -l < "$MOCK_STATUS_CALLS")
		case "$MOCK_STATUS_MODE" in
		unchanged) owner=node0 ;;
		transition)
			if (( call_count <= 2 )); then owner=node0; else owner=node1; fi
			;;
		blind) return 1 ;;
		*) owner=node0 ;;
		esac
		if [[ "$node" == "$FW0" ]]; then mock_status "$owner" node0
		elif [[ "$node" == "$FW1" ]]; then mock_status "$owner" node1
		else printf 'unknown fixture node: %s\n' "$node" >&2; return 91
		fi
		return 0
	fi
	if [[ "$node" == "$CLUSTER_LAN_HOST" && "$args" == *' tail '* ]]; then
		case "$MOCK_LOG_MODE" in
		empty) return 0 ;;
		short) mock_log 3 healthy ;;
		dead) mock_log 8 dead ;;
		healthy) mock_log 8 healthy ;;
		*) printf 'unknown log fixture: %s\n' "$MOCK_LOG_MODE" >&2; return 92 ;;
		esac
		return 0
	fi
	if [[ "$args" == *'request chassis cluster failover'* ]]; then
		if [[ "$MOCK_REQUEST_MODE" == fail ]]; then
			printf 'error: failover request refused\n' >&2
			return 1
		fi
		return 0
	fi
	printf 'unexpected mocked incus command: %s\n' "$args" >&2
	return 93
}

# Counter-based poll budgets do not depend on this stub; keeping it a no-op
# makes the 200-run hermetic loop fast without changing attempt accounting.
sleep() { :; }

# (a) Empty tail must FAIL, never `all streams alive ()`.
PASS=0; FAIL=0; MOCK_LOG_MODE=empty
if check_streams 'empty-tail fixture' >"${TMP_DIR}/empty.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 &&
	$(<"${TMP_DIR}/empty.out") == *'short stream read (0/8 rows'* &&
	$(<"${TMP_DIR}/empty.out") != *'all streams alive'* ]]; then
	ok 'empty-tail stream snapshot FAILs closed'
else
	bad "empty-tail stream snapshot did not FAIL closed (rc=$rc, output=$(<"${TMP_DIR}/empty.out"))"
fi

# Short but non-empty tails are also blind; exact stream count is required.
PASS=0; FAIL=0; MOCK_LOG_MODE=short
if check_streams 'short-tail fixture' >"${TMP_DIR}/short.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 &&
	$(<"${TMP_DIR}/short.out") == *'short stream read (3/8 rows'* ]]; then
	ok 'short stream snapshot FAILs rather than treating missing rows as alive'
else
	bad "short stream snapshot result unexpected (rc=$rc, output=$(<"${TMP_DIR}/short.out"))"
fi

# Positive control: a full set of live stream rows passes.
PASS=0; FAIL=0; MOCK_LOG_MODE=healthy
if check_streams 'healthy fixture' >"${TMP_DIR}/healthy.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 0 && "$PASS" -eq 1 && "$FAIL" -eq 0 &&
	$(<"${TMP_DIR}/healthy.out") == *'all streams alive'* ]]; then
	ok 'complete healthy stream snapshot passes'
else
	bad "healthy stream snapshot result unexpected (rc=$rc, output=$(<"${TMP_DIR}/healthy.out"))"
fi

# A complete read with a dead stream remains a measured FAIL.
PASS=0; FAIL=0; MOCK_LOG_MODE=dead
if check_streams 'dead-stream fixture' >"${TMP_DIR}/dead.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 &&
	$(<"${TMP_DIR}/dead.out") == *'1/8 streams dead'* ]]; then
	ok 'complete snapshot with a dead stream FAILs'
else
	bad "dead-stream snapshot result unexpected (rc=$rc, output=$(<"${TMP_DIR}/dead.out"))"
fi

# Both independently captured FormatStatus shapes must agree on the owner.
status_fw0_node0=$(mock_status node0 node0)
status_fw1_node1=$(mock_status node0 node1)
if stress_rg1_owner_verdict node0 "$status_fw0_node0" "$status_fw1_node1"; then
	ok 'both node queries prove the expected RG1 owner'
else
	bad 'both node queries rejected the expected RG1 owner'
fi

# A real RG1 split while RG0 and RG2 remain on node0, as they do after an
# RG1-only move: only RG1 decides the result (kills RG0/RG2 scope mutants).
status_fw0_node0=$(mock_status node1 node0 node0)
status_fw1_node1=$(mock_status node1 node1 node0)
if stress_rg1_owner_verdict node1 "$status_fw0_node0" "$status_fw1_node1"; then
	ok 'RG1 owner verdict is scoped to RG1, not RG0 or RG2'
else
	bad 'RG0/RG2 state contaminated RG1 owner verdict'
fi

# Captured FormatStatus outputs from the real cluster renderer after an
# untargeted ManualFailover(1): fw0's local node is secondary-hold/Manual yes,
# and both views show node1 primary. Keep these verbatim to pin parser drift.
cat > "$TMP_DIR/real-moved-fw0.txt" <<'REAL_FW0'
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    IF  Interface monitoring        IP  IP monitoring
    CF  Config Sync monitoring

Cluster ID: 1
Node name: node0

HA protocol version: 1
Session-sync wire version: 2
Peer software version: unknown
Peer HA protocol version: 1
Peer session-sync wire version: unknown

Node   Priority Status         Preempt  Manual   Monitor-failures

Redundancy group: 0 , Failover count: 0
node0  200      primary        no       no       None
  Takeover ready: no
  Transfer ready: yes
node1  100      secondary      no       no       None

Redundancy group: 1 , Failover count: 1
node0  200      secondary-hold no       yes      None
  Takeover ready: no
  Transfer ready: yes
node1  100      primary        no       no       None

Redundancy group: 2 , Failover count: 0
node0  200      primary        no       no       None
  Takeover ready: no
  Transfer ready: yes
node1  100      secondary      no       no       None
REAL_FW0
cat > "$TMP_DIR/real-moved-fw1.txt" <<'REAL_FW1'
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    IF  Interface monitoring        IP  IP monitoring
    CF  Config Sync monitoring

Cluster ID: 1
Node name: node1

HA protocol version: 1
Session-sync wire version: 2
Peer software version: unknown
Peer HA protocol version: 1
Peer session-sync wire version: unknown

Node   Priority Status         Preempt  Manual   Monitor-failures

Redundancy group: 0 , Failover count: 1
node1  100      secondary      no       no       None
  Takeover ready: yes
  Transfer ready: yes
node0  200      primary        no       no       None

Redundancy group: 1 , Failover count: 1
node1  100      primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
node0  200      secondary-hold no       no       None

Redundancy group: 2 , Failover count: 1
node1  100      secondary      no       no       None
  Takeover ready: yes
  Transfer ready: yes
node0  200      primary        no       no       None
REAL_FW1
real_moved_fw0=$(<"$TMP_DIR/real-moved-fw0.txt")
real_moved_fw1=$(<"$TMP_DIR/real-moved-fw1.txt")
if stress_rg1_owner_verdict node1 "$real_moved_fw0" "$real_moved_fw1"; then
	ok 'real FormatStatus secondary-hold views settle on the new primary'
else
	bad 'real FormatStatus secondary-hold views did not settle'
fi
if stress_rg1_owner_verdict node0 "$real_moved_fw0" "$real_moved_fw1" >"${TMP_DIR}/real-old-owner.out"; then
	bad 'real moved-to-node1 output proved the old node0 owner'
else
	ok 'real moved-to-node1 output does not prove the old node0 owner'
fi
hold_fw0=$(mock_status node1 node0 node0 yes yes)
hold_fw1=$(mock_status node1 node1 node0 yes yes)
if stress_rg1_owner_verdict node1 "$hold_fw0" "$hold_fw1" &&
	[[ "$hold_fw0" == *'secondary-hold no       yes'* &&
		"$hold_fw0" == *'Transfer ready: yes'* &&
		"$hold_fw1" == *'(local: transfer-out override)'* ]]; then
	ok 'Manual secondary-hold, Transfer-ready, and peer override annotation settle'
else
	bad 'FormatStatus-shaped hold fixture did not preserve renderer fields or settle'
fi

# One query at a time reports a different owner: neither direction is settled.
split_fw0_moved=$(mock_status node1 node0 node0 yes)
split_fw1_stale=$(mock_status node0 node1 node0)
if stress_rg1_owner_verdict node1 "$split_fw0_moved" "$split_fw1_stale" >"${TMP_DIR}/split-fw0-moved.out"; then
	bad 'split view with only fw0 showing the new owner was accepted'
else
	ok 'split view with only fw0 showing the new owner FAILs'
fi
split_fw0_stale=$(mock_status node0 node0 node0)
split_fw1_moved=$(mock_status node1 node1 node0 yes)
if stress_rg1_owner_verdict node1 "$split_fw0_stale" "$split_fw1_moved" >"${TMP_DIR}/split-fw1-moved.out"; then
	bad 'split view with only fw1 showing the new owner was accepted'
else
	ok 'split view with only fw1 showing the new owner FAILs'
fi

# A duplicate RG1 node row is malformed evidence, not a settled owner.
duplicate_status=$(mock_status node0 node0 | awk '
	/^Redundancy group: 1 ,/ { print; print "node0  200      primary        no       no       None"; next }
	{ print }
')
if stress_rg1_owner_verdict node0 "$duplicate_status" "$(mock_status node0 node1 node0)" >"${TMP_DIR}/duplicate-row.out"; then
	bad 'duplicate RG1 node row was accepted as settled'
elif [[ $(<"${TMP_DIR}/duplicate-row.out") == *'BLIND'* ]]; then
	ok 'duplicate RG1 node row is reported BLIND'
else
	bad 'duplicate RG1 node row failed without a BLIND reason'
fi
# Unchanged, valid node0-primary fixtures MUST FAIL a node1-expected move.
status_fw0_node0=$(mock_status node0 node0)
status_fw1_node1=$(mock_status node0 node1)
if stress_rg1_owner_verdict node1 "$status_fw0_node0" "$status_fw1_node1" >"${TMP_DIR}/unchanged-verdict.out"; then
	bad 'unchanged RG1 owner passed the node1 ownership verdict'
else
	ok 'unchanged RG1 owner fails the node1 ownership verdict'
fi
if stress_rg1_owner_verdict node1 '' '' >"${TMP_DIR}/blind-verdict.out"; then
	bad 'empty status queries passed the ownership verdict'
else
	if [[ $(<"${TMP_DIR}/blind-verdict.out") == *'BLIND'* ]]; then
		ok 'empty status queries are blind, not a healthy owner'
	else
		bad 'empty status queries lacked a blind-evidence reason'
	fi
fi
# Both queries claiming primary is split-brain evidence, never a settled owner.
dual_fw0=$(printf 'Redundancy group: 1 , Failover count: 1\nnode0  200      primary        no       no       None\n  Takeover ready: yes\n  Transfer ready: yes\nnode1  100      primary        no       no       None\n')
dual_fw1=$(printf 'Redundancy group: 1 , Failover count: 1\nnode1  100      primary        no       no       None\n  Takeover ready: yes\n  Transfer ready: yes\nnode0  200      primary        no       no       None\n')
if stress_rg1_owner_verdict node0 "$dual_fw0" "$dual_fw1" >/dev/null ||
	stress_rg1_owner_verdict node1 "$dual_fw0" "$dual_fw1" >/dev/null; then
	bad 'dual-primary RG1 views were accepted for an expected owner'
else
	ok 'dual-primary RG1 views FAIL for either expected owner'
fi

# A hold without any primary does not prove ownership.
noprim_fw0=$(printf 'Redundancy group: 1 , Failover count: 1\nnode0  200      secondary-hold no       yes      None\n  Takeover ready: yes\n  Transfer ready: yes\nnode1  100      secondary      no       no       None\n')
noprim_fw1=$(printf 'Redundancy group: 1 , Failover count: 1\nnode1  100      secondary      no       no       None\n  Takeover ready: yes\n  Transfer ready: yes\nnode0  200      secondary-hold no       no       None\n')
if stress_rg1_owner_verdict node0 "$noprim_fw0" "$noprim_fw1" >/dev/null; then
	bad 'no-primary (hold + secondary) RG1 views were accepted as settled'
else
	ok 'no-primary (hold + secondary) RG1 views FAIL'
fi

# Verbatim renderer output during in-grace failback: the peer may be held while
# the expected node0 owner is already primary in both views.
real_fb_ingrace_fw0=$(cat <<'REAL_FB_INGRACE_FW0'
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    IF  Interface monitoring        IP  IP monitoring
    CF  Config Sync monitoring

Cluster ID: 1
Node name: node0

HA protocol version: 1
Session-sync wire version: 2
Peer software version: unknown
Peer HA protocol version: 1
Peer session-sync wire version: unknown

Node   Priority Status         Preempt  Manual   Monitor-failures

Redundancy group: 0 , Failover count: 0
node0  200      primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
node1  100      secondary      no       no       None

Redundancy group: 1 , Failover count: 1
node0  200      primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
node1  100      secondary-hold (local: transfer-commit grace) no       no       None

Redundancy group: 2 , Failover count: 0
node0  200      primary        no       no       None
  Takeover ready: yes
  Transfer ready: yes
node1  100      secondary      no       no       None
REAL_FB_INGRACE_FW0
)
real_fb_ingrace_fw1=$(cat <<'REAL_FB_INGRACE_FW1'
Monitor Failure codes:
    CS  Cold Sync monitoring        FL  Fabric Connection monitoring
    IF  Interface monitoring        IP  IP monitoring
    CF  Config Sync monitoring

Cluster ID: 1
Node name: node1

HA protocol version: 1
Session-sync wire version: 2
Peer software version: unknown
Peer HA protocol version: 1
Peer session-sync wire version: unknown

Node   Priority Status         Preempt  Manual   Monitor-failures

Redundancy group: 0 , Failover count: 0
node1  100      secondary      no       no       None
  Takeover ready: yes
  Transfer ready: yes
node0  200      primary        no       no       None

Redundancy group: 1 , Failover count: 1
node1  100      secondary      no       no       None
  Takeover ready: yes
  Transfer ready: yes
node0  200      primary        no       no       None

Redundancy group: 2 , Failover count: 0
node1  100      secondary      no       no       None
  Takeover ready: yes
  Transfer ready: yes
node0  200      primary        no       no       None
REAL_FB_INGRACE_FW1
)
if stress_rg1_owner_verdict node0 "$real_fb_ingrace_fw0" "$real_fb_ingrace_fw1"; then
	ok 'real in-grace failback render settles on node0'
else
	bad 'real in-grace failback render did not settle on node0'
fi


# Bounded-poll no-op fixture: node0 remains primary in BOTH node queries.
# It must time out as FAIL and must have queried both nodes on every attempt.
PASS=0; FAIL=0; MOCK_STATUS_MODE=unchanged; : > "$MOCK_STATUS_CALLS"
# shellcheck disable=SC2034  # consumed by stress-failover-lib.sh
STRESS_OWNER_TIMEOUT=2
# shellcheck disable=SC2034  # consumed by stress-failover-lib.sh
STRESS_OWNER_INTERVAL=1
if wait_rg1_owner node1 'unchanged-status fixture' >"${TMP_DIR}/unchanged-poll.out" 2>&1; then rc=0; else rc=$?; fi
call_count=$(wc -l < "$MOCK_STATUS_CALLS")
if [[ "$rc" -eq 1 && "$FAIL" -eq 1 && "$PASS" -eq 0 && "$call_count" -eq 6 &&
	$(<"${TMP_DIR}/unchanged-poll.out") == *'RG1 did not move'* ]]; then
	ok 'unchanged-status bounded poll FAILs after querying both nodes on each attempt'
else
	bad "unchanged-status poll result unexpected (rc=$rc, reads=$call_count, output=$(<"${TMP_DIR}/unchanged-poll.out"))"
fi

# Positive control: transition on the second bounded poll is observed from both nodes.
PASS=0; FAIL=0; MOCK_STATUS_MODE=transition; : > "$MOCK_STATUS_CALLS"
# shellcheck disable=SC2034  # consumed by stress-failover-lib.sh
STRESS_OWNER_TIMEOUT=4
if wait_rg1_owner node1 'settling-status fixture' >"${TMP_DIR}/settled-poll.out" 2>&1; then rc=0; else rc=$?; fi
call_count=$(wc -l < "$MOCK_STATUS_CALLS")
if [[ "$rc" -eq 0 && "$PASS" -eq 1 && "$FAIL" -eq 0 && "$call_count" -eq 4 &&
	$(<"${TMP_DIR}/settled-poll.out") == *'settled on node1'* ]]; then
	ok 'bounded poll accepts a move observed on both nodes'
else
	bad "settling-status poll result unexpected (rc=$rc, reads=$call_count, output=$(<"${TMP_DIR}/settled-poll.out"))"
fi

# CLI refusal output is stderr in production; the request wrapper preserves it
# in the transcript but leaves the authoritative owner poll to decide outcome.
MOCK_REQUEST_MODE=fail
if stress_request fw0 'request chassis cluster failover redundancy-group 1' >"${TMP_DIR}/request-fail.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 0 && $(<"${TMP_DIR}/request-fail.out") == *'returned 1'* &&
	$(<"${TMP_DIR}/request-fail.out") == *'failover request refused'* ]]; then
	ok 'request refusal and stderr text are retained for diagnosis'
else
	bad "request refusal was not retained (rc=$rc, output=$(<"${TMP_DIR}/request-fail.out"))"
fi
MOCK_REQUEST_MODE=success
if stress_request fw0 'request chassis cluster failover redundancy-group 1' >"${TMP_DIR}/request-ok.out" 2>&1; then rc=0; else rc=$?; fi
if [[ "$rc" -eq 0 && ! -s "${TMP_DIR}/request-ok.out" ]]; then
	ok 'silent successful request does not add noisy transcript output'
else
	bad "successful request result unexpected (rc=$rc, output=$(<"${TMP_DIR}/request-ok.out"))"
fi

# Whole-script fixtures: unchanged-owner FAIL control, real-output mover
# positive control, and a mover that remains on fw1 after failback. The latter
# pins the final-owner check independently of the per-cycle poll.
whole_dir="${TMP_DIR}/whole-script"
mkdir -p "$whole_dir/bin"
mock_status node0 node0 node0 > "$whole_dir/init-fw0.txt"
mock_status node0 node1 node0 > "$whole_dir/init-fw1.txt"
mock_status node1 node0 node0 > "$whole_dir/reset-fw0.txt"
mock_status node1 node1 node0 > "$whole_dir/reset-fw1.txt"
cp "$TMP_DIR/real-moved-fw0.txt" "$whole_dir/moved-fw0.txt"
cp "$TMP_DIR/real-moved-fw1.txt" "$whole_dir/moved-fw1.txt"
mock_log 8 healthy > "$whole_dir/iperf.log"
cat > "$whole_dir/bin/incus" <<'MOCK_INCUS'
#!/usr/bin/env bash
if [[ "${1:-}" == list ]]; then exit 0; fi
if [[ "${1:-}" == info ]]; then printf 'Status: RUNNING\n'; exit 0; fi
if [[ "${1:-}" != exec ]]; then
printf 'unexpected fixture incus call: %s\n' "$*" >&2
exit 90
fi
shift
node="$1"
shift
args="$*"
case "$args" in
*"show chassis cluster status"*)
printf '%s\n' "$node" >> "${WHOLE_STATUS_CALLS:?}"
case "$node" in
fw0) cat "${WHOLE_FW0:?}" ;;
fw1) cat "${WHOLE_FW1:?}" ;;
*) printf 'unknown status node: %s\n' "$node" >&2; exit 92 ;;
esac
;;
*"show security flow session destination-prefix"*)
for id in 1 2 3 4 5 6 7 8; do printf 'Session ID: %s\n' "$id"; done
;;
*"request chassis cluster failover reset redundancy-group 1"*)
if [[ "$WHOLE_MODE" != unchanged ]]; then
cp "${WHOLE_RESET_FW0:?}" "$WHOLE_FW0"
cp "${WHOLE_RESET_FW1:?}" "$WHOLE_FW1"
fi
;;
*"request chassis cluster failover redundancy-group 1 node 0"*)
if [[ "$WHOLE_MODE" == mover || ! -s "${WHOLE_MOVED_MARKER:?}" ]]; then
cp "${WHOLE_INIT_FW0:?}" "$WHOLE_FW0"
cp "${WHOLE_INIT_FW1:?}" "$WHOLE_FW1"
fi
;;
*"request chassis cluster failover redundancy-group 1"*)
if [[ "$WHOLE_MODE" != unchanged ]]; then
cp "${WHOLE_MOVED_FW0:?}" "$WHOLE_FW0"
cp "${WHOLE_MOVED_FW1:?}" "$WHOLE_FW1"
printf 'moved\n' > "${WHOLE_MOVED_MARKER:?}"
fi
;;
*"pgrep -x iperf3"*|*"ping "*|*"pkill -9 iperf3"*|*"bash -c"*)
exit 0
;;
*"tail "*|*"grep "*)
cat "${WHOLE_IPERF_LOG:?}"
;;
*)
printf 'unhandled fixture incus command: %s\n' "$args" >&2
exit 91
;;
esac
MOCK_INCUS
cat > "$whole_dir/bin/sleep" <<'MOCK_SLEEP'
#!/usr/bin/env bash
exit 0
MOCK_SLEEP
chmod +x "$whole_dir/bin/incus" "$whole_dir/bin/sleep"
whole_harness="${STRESS_FAILOVER_HARNESS:-${SCRIPT_DIR}/test-stress-failover.sh}"
whole_lock="${whole_dir}/cluster.lock"
run_whole_harness() {
local mode="$1"
cp "$whole_dir/init-fw0.txt" "$whole_dir/current-fw0.txt"
cp "$whole_dir/init-fw1.txt" "$whole_dir/current-fw1.txt"
: > "$whole_dir/status-calls"
: > "$whole_dir/moved.marker"
if env \
PATH="$whole_dir/bin:$PATH" \
BPFRX_CLUSTER_ENV="" \
FW0=fw0 FW1=fw1 CLUSTER_LAN_HOST=lan \
TOTAL_CYCLES=1 FAILOVER_INTERVAL=2 IPERF_STREAMS=8 \
STRESS_OWNER_TIMEOUT=0 STRESS_OWNER_INTERVAL=1 \
XPF_CLUSTER_LOCK="$whole_lock" XPF_CLUSTER_LOCK_HELD="$whole_lock:$$" \
WHOLE_MODE="$mode" \
WHOLE_STATUS_CALLS="$whole_dir/status-calls" \
WHOLE_FW0="$whole_dir/current-fw0.txt" WHOLE_FW1="$whole_dir/current-fw1.txt" \
WHOLE_INIT_FW0="$whole_dir/init-fw0.txt" WHOLE_INIT_FW1="$whole_dir/init-fw1.txt" \
WHOLE_RESET_FW0="$whole_dir/reset-fw0.txt" WHOLE_RESET_FW1="$whole_dir/reset-fw1.txt" \
WHOLE_MOVED_FW0="$whole_dir/moved-fw0.txt" WHOLE_MOVED_FW1="$whole_dir/moved-fw1.txt" \
WHOLE_MOVED_MARKER="$whole_dir/moved.marker" \
WHOLE_IPERF_LOG="$whole_dir/iperf.log" \
bash "$whole_harness" > "$whole_dir/run-${mode}.out" 2>&1; then
WHOLE_RC=0
else
WHOLE_RC=$?
fi
WHOLE_READS=$(wc -l < "$whole_dir/status-calls")
}

run_whole_harness unchanged
if [[ "$WHOLE_RC" -eq 1 && "$WHOLE_READS" -eq 8 && \
$(<"$whole_dir/run-unchanged.out") == *'cycle 1 failover: RG1 did not move'* && \
$(<"$whole_dir/run-unchanged.out") == *'all streams alive'* && \
$(<"$whole_dir/run-unchanged.out") == *'iperf3 throughput: 8.0000 Gbps'* && \
$(<"$whole_dir/run-unchanged.out") != *'all 1 failover cycles completed'* ]]; then
ok 'whole harness rejects unchanged ownership while healthy traffic and final SUM pass'
else
bad "unchanged-owner whole harness unexpected (rc=$WHOLE_RC, reads=$WHOLE_READS, output=$(<"$whole_dir/run-unchanged.out"))"
fi

run_whole_harness mover
if [[ "$WHOLE_RC" -eq 0 && "$WHOLE_READS" -eq 8 && \
$(<"$whole_dir/run-mover.out") == *'cycle 1 failover: RG1 settled on node1'* && \
$(<"$whole_dir/run-mover.out") == *'cycle 1 failback: RG1 settled on node0'* && \
$(<"$whole_dir/run-mover.out") == *'final RG1 owner is fw0 (both node queries)'* && \
$(<"$whole_dir/run-mover.out") == *'all 1 failover cycles completed'* ]]; then
ok 'whole harness accepts real-output mover and proves failback/final fw0 owner'
else
bad "real-output mover whole harness unexpected (rc=$WHOLE_RC, reads=$WHOLE_READS, output=$(<"$whole_dir/run-mover.out"))"
fi

run_whole_harness stuck
if [[ "$WHOLE_RC" -eq 1 && "$WHOLE_READS" -eq 8 && \
$(<"$whole_dir/run-stuck.out") == *'cycle 1 failback: RG1 did not move'* && \
$(<"$whole_dir/run-stuck.out") == *'final RG1 owner is not proven on fw0'* && \
$(<"$whole_dir/run-stuck.out") != *'all 1 failover cycles completed'* ]]; then
ok 'whole harness rejects a stuck-after-failback owner and reports final owner unproven'
else
bad "stuck-after-failback whole harness unexpected (rc=$WHOLE_RC, reads=$WHOLE_READS, output=$(<"$whole_dir/run-stuck.out"))"
fi

printf '%s\n' '----------------------------------------'
printf 'stress failover selftest: %d passed, %d failed\n' "$SELFTEST_PASS" "$SELFTEST_FAIL"
[[ "$SELFTEST_FAIL" -eq 0 ]]
