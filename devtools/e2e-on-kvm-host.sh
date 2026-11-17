#!/usr/bin/env bash
# Purpose: run BeastBoot's beast-net unit suite, the helper build, the disk fixtures, the Disk tools
#          QEMU e2e (tests/e2e/test_e2e_disks.py) and the general e2e suite (tests/e2e: menu, recipes,
#          Secure Boot, beast-net) on an x86 Linux server with KVM (ssh host: --host or BB_E2E_HOST), unprivileged.
# Usage:   devtools/e2e-on-kvm-host.sh [--host H] [--cpus N] [--mem GB] [--build-arg K=V] [--yes] STEP [-- PYTEST_ARGS...]
#   STEP     sync      copy the sources (git-tracked + untracked-not-ignored; never keys/.env/.agent/.git/dist)
#            image     build the images beast-disks-build (build/Containerfile) and beast-disks-env
#            unit      beastnet/tests                      (PYTEST_ARGS e.g. -- -k addons)
#            helper    test key + build/build.sh; checks the helper app is in the helper initramfs
#            fixtures  disk fixtures, built inside a throw-away KVM guest (cached by recipe hash)
#            lock      regenerate build/beastnet/packages.lock there and copy it back here
#            disks     tests/e2e/test_e2e_disks.py + test_e2e_disks_copy.py (PYTEST_ARGS e.g. -- -k rescue)
#            e2e       pytest on the files and options after -- (e.g. -- tests/e2e/test_e2e_smoke.py -k uefi;
#                      also other suites: -- installer/tests tests/menu devtools/tests); without them
#                      tests/e2e except the two Disk tools files. Needs the helper step's dist.
#            signflow  the release's signing split: build unsigned, build/sign.sh with a second key, two
#                      key-less rebuilds that must be byte-identical (docs/RELEASING.md)
#            sbom      build/verify-dist.sh (arguments after -- go to it, e.g. -- --rebuild) and
#                      scripts/gen_sbom.py on the helper step's dist (no scan)
#            sbomcheck scripts/sbom-vuln.sh sbom (SBOM + its validation, with the pinned tools it downloads)
#                      and scripts/selftest.py on the helper step's dist
#            vulnscan  scripts/sbom-vuln.sh sbom + scan on the helper step's dist: grype and osv-scanner with the
#                      OpenVEX triage, and the boot-chain checks (SBAT, signers, dbx). Scan options after --
#                      (e.g. -- --fail-on critical). The reports are copied to .agent/scratch/kvm-host/vulns/
#            kernelvex after a kernel update: scan, scripts/kernel_vex.py, scan again; copies the new
#                      sbom/vex.kernel.openvex.json back here (review and commit it)
#            all       sync image unit helper fixtures disks (goes on after a failed step)
#            status    what runs and what is left on the host
#            clean     remove our containers, images and ~/vms/beast-disks, but keep the fixture
#                      cache (~/vms/beast-disks/cache/disk-fixtures); with --yes remove that too
#   --cpus/--mem  container limits (default and maximum 6 CPUs and 12 GB, shared host; one container at a time)
# Logs: .agent/scratch/kvm-host/<step>.log (full); the terminal gets a PASS/FAIL summary.
# Host rules (enforced in run_container): no --privileged/--cap-add/host network/pid/ipc, the only
# device is /dev/kvm, the only mount is ~/vms/beast-disks, containers are named beast-disks-*,
# default (NAT) networking, no published ports, nice 10. Privileged fixture work runs in a guest.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST="${BB_E2E_HOST:-}"
CPUS=6
MEM=12
YES=0
LOGS="$ROOT/.agent/scratch/kvm-host"
BASE_REF="docker.io/library/ubuntu:26.04@sha256:c098726dd9b9733f3e885f8de0ef375206a311b0a317eadc40d347b1115fb944"
R=""   # remote work dir, set by init_remote
# extra build args for build/Containerfile (pins gone from the archive): --build-arg NAME=VERSION
BUILD_ARGS=()

log() { printf '[asc %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "error: $*"; exit 1; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit "${1:-0}"; }
# ssh with retries: exit 255 is ssh's own failure (VPN drop, "Network is unreachable"), not the
# remote command's, so it is retried for about 10 minutes. Use rr only for commands safe to repeat.
rr() {
  local rc i
  for i in $(seq 1 40); do
    rc=0
    ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 "$HOST" "$@" || rc=$?
    [ "$rc" = 255 ] || return "$rc"
    log "ssh to $HOST failed (try $i), retrying in 15 s"; sleep 15
  done
  die "lost $HOST for 10 minutes; jobs keep running there, rerun the same step to reattach"
}
fetch() { # REMOTE_PATH LOCAL_PATH, retried like rr
  local i
  for i in $(seq 1 20); do scp -q "$HOST:$1" "$2" && return 0; sleep 15; done
  log "could not fetch $1"; return 1
}

init_remote() {
  local home
  # shellcheck disable=SC2016  # $HOME of the remote user
  home="$(rr 'printf %s "$HOME"')" || die "cannot reach $HOST"
  R="$home/vms/beast-disks"
  mkdir -p "$LOGS"
}

tags() { # prints: build-tag env-tag
  local h1 h2
  h1="$(cd "$ROOT" && git ls-files -co --exclude-standard build/Containerfile build/grub build/shim | sort \
        | xargs cat | cat - <(printf '%s\n' "${BUILD_ARGS[@]}") | shasum -a 256 | cut -c1-12)"
  h2="$(printf '%s' "$h1" | cat - "$SCRIPT_DIR/e2e-kvm-host/Dockerfile" | shasum -a 256 | cut -c1-12)"
  echo "beast-disks-build:$h1 beast-disks-env:$h2"
}

# --- host-rule guard -------------------------------------------------------------------------
guard_docker_args() { # every docker run on the host passes through here
  local a prev="" vols=0
  for a in "$@"; do
    case "$a" in
      --privileged*|--cap-add*|--security-opt*|--network*|--net|--net=*|--pid|--pid=*|--ipc*|--uts*|--userns*|-p|--publish*|-P|--cgroupns*)
        die "refusing docker argument $a on $HOST (host rules)" ;;
    esac
    case "$prev" in
      --device) [ "$a" = /dev/kvm ] || die "refusing device $a (only /dev/kvm)" ;;
      -v) vols=$((vols + 1)); [ "${a%%:*}" = "$R" ] || die "refusing mount $a (only $R)" ;;
      --name) case "$a" in beast-disks-*) ;; *) die "container name must start with beast-disks-" ;; esac ;;
    esac
    case "$a" in --device=*|--volume*|--mount*|-v?*) die "use the split form for $a" ;; esac
    prev="$a"
  done
  [ "$vols" -le 1 ] || die "only one mount allowed"
}

# --- remote jobs (detached on the host, polled from here) -------------------------------------
busy() { rr "docker ps -q --filter name=^beast-disks-" | grep -q .; }

job_running() { rr "test -d '$R/state/$1.lock' && ! test -f '$R/logs/$1.rc'"; }

remote_job() { # NAME then the command line (argv), run detached with nohup; returns its exit status.
  # A job still running from an earlier (disconnected) call is reattached, not started again; the
  # lock directory makes a retried start a no-op.
  local name="$1"; shift
  local cmd="" a rc
  if job_running "$name"; then
    log "$name is already running on $HOST: reattaching"
  else
    for a in "$@"; do cmd+="$(printf '%q ' "$a")"; done
    printf '#!/usr/bin/env bash\nmkdir %q 2>/dev/null || exit 0\ncd %q\n%s > %q 2>&1\necho $? > %q\n' \
      "$R/state/$name.lock" "$R" "$cmd" "$R/logs/$name.log" "$R/logs/$name.rc" > "$LOGS/job-$name.sh"
    rr "mkdir -p '$R/logs' '$R/state' && rm -rf '$R/logs/$name.rc' '$R/state/$name.lock' && cat > '$R/state/job-$name.sh'" \
      < "$LOGS/job-$name.sh"
    rr "nohup setsid bash '$R/state/job-$name.sh' >/dev/null 2>&1 < /dev/null &"
  fi
  local t0 n=0; t0="$(date +%s)"
  while ! rr "test -f '$R/logs/$name.rc'"; do
    sleep 20; n=$((n + 1))
    [ $((n % 6)) -eq 0 ] && log "$name running $(( ($(date +%s) - t0) / 60 )) min: $(rr "tail -n 1 '$R/logs/$name.log' 2>/dev/null | cut -c1-110" || true)"
  done
  rc="$(rr "cat '$R/logs/$name.rc'")"
  fetch "$R/logs/$name.log" "$LOGS/$name.log" || true
  return "$rc"
}

run_container() { # STEP [ARGS...]: one container from the env image, under the guard
  local step="$1"; shift
  local env_tag kvm_gid uid gid epoch
  env_tag="$(tags | cut -d' ' -f2)"
  if ! job_running "$step" && busy; then die "a beast-disks-* container is already running (one at a time; see status)"; fi
  # shellcheck disable=SC2016  # evaluated on the host
  read -r uid gid kvm_gid < <(rr 'echo "$(id -u) $(id -g) $(getent group kvm | cut -d: -f3)"')
  epoch="$(cd "$ROOT" && git log -1 --format=%ct)"
  # lock: root inside the container only to run `apt-get update` (system apt lists), then
  # inside.sh drops to the host user with setpriv, so no file it writes is root-owned
  local user="$uid:$gid"
  [ "$step" = lock ] && user=0:0
  local -a args=(run --rm --init --name "beast-disks-$step" --user "$user" --group-add "$kvm_gid"
    -e "HOST_UID=$uid" -e "HOST_GID=$gid"
    --device /dev/kvm --cpus "$CPUS" --memory "${MEM}g" --memory-swap "${MEM}g" --pids-limit 8192
    -e "SOURCE_DATE_EPOCH=$epoch" -v "$R:/w" -w /w/src/BeastBoot "$env_tag"
    bash /w/src/BeastBoot/devtools/e2e-kvm-host/inside.sh "$step" "$@")
  guard_docker_args "${args[@]}"
  seed_tools "$env_tag" "$uid:$gid"
  remote_job "$step" nice -n 10 docker "${args[@]}"
}

seed_tools() { # ENV_TAG UID:GID: copy the image's /src/.tools (GRUB build, Debian shim; partly root-only)
  # to ~/vms/beast-disks/tools once, as root inside the container, then hand it to the host user
  rr "test -d '$R/tools/cache/grub-src'" && return 0
  local -a args=(run --rm --name beast-disks-seed --cpus 2 -v "$R:/w" "$1"
    sh -c "mkdir -p /w/tools && cp -a /src/.tools/. /w/tools/ && chown -R $2 /w/tools")
  guard_docker_args "${args[@]}"
  rr "$(printf '%q ' docker "${args[@]}")" || die "seeding $R/tools failed"
}

# --- steps -----------------------------------------------------------------------------------
step_sync() {
  local list="$LOGS/files.lst" bad
  (cd "$ROOT" && git ls-files -co --exclude-standard) \
    | grep -vE '(^|/)keys/|\.(key|p12|pfx)$|(^|/)\.env$|^\.agent/|^\.git/|^\.tools|^\.venv/|^dist/|^out/' > "$list"
  bad="$(grep -E '(^|/)keys/|\.key$|(^|/)\.env|^\.agent/|^\.git/|^dist/' "$list" || true)"
  [ -z "$bad" ] || die "secret-like paths in the copy list: $bad"
  # rsync into a staging copy (resumable: a retry sends only what is missing), then swap it in
  local i ok=0
  rr "mkdir -p '$R/src/BeastBoot.next'"
  for i in $(seq 1 20); do
    if (cd "$ROOT" && rsync -a --partial --timeout=60 --files-from="$list" -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
        ./ "$HOST:$R/src/BeastBoot.next/"); then ok=1; break; fi
    log "rsync failed (try $i), retrying in 15 s"; sleep 15
  done
  [ "$ok" = 1 ] || die "rsync to $HOST failed"
  rr "rm -rf '$R/src/BeastBoot' && mv '$R/src/BeastBoot.next' '$R/src/BeastBoot'"
  rr "find '$R/src' \\( -name '*.key' -o -name '.env' -o -path '*/keys/*' \\) | grep -q . && exit 1 || true" \
    || die "a key file reached $HOST"
  log "RESULT sync PASS $(wc -l < "$list" | tr -d ' ') files"
}

step_image() {
  local bt et
  # the build containers get the same CPU/memory cap as the test containers
  local -a limits=(--force-rm --cpu-period 100000 --cpu-quota "$((CPUS * 100000))" --memory "${MEM}g" --memory-swap "${MEM}g")
  local a; for a in "${BUILD_ARGS[@]}"; do limits+=(--build-arg "$a"); done
  read -r bt et < <(tags)
  busy && die "a beast-disks-* container is running"
  rr "mkdir -p '$R/state'; docker image inspect '$BASE_REF' >/dev/null 2>&1 || touch '$R/state/pulled-base'"
  if ! rr "docker image inspect '$bt' >/dev/null 2>&1"; then
    log "building $bt from build/Containerfile (GRUB from source; takes a while)"
    remote_job image-build nice -n 10 docker build -q "${limits[@]}" -t "$bt" -f "$R/src/BeastBoot/build/Containerfile" "$R/src/BeastBoot" \
      || { log "RESULT image FAIL build image (see $LOGS/image-build.log)"; return 1; }
  fi
  if ! rr "docker image inspect '$et' >/dev/null 2>&1"; then
    log "building $et"
    remote_job image-env nice -n 10 docker build -q "${limits[@]}" --build-arg "BASE=$bt" -t "$et" "$R/src/BeastBoot/devtools/e2e-kvm-host" \
      || { log "RESULT image FAIL env image (see $LOGS/image-env.log)"; return 1; }
  fi
  # older tags of our two images (an earlier Containerfile or Dockerfile) are dropped
  rr "for t in \$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^beast-disks-(build|env):'); do
        [ \"\$t\" = '$bt' ] || [ \"\$t\" = '$et' ] || docker rmi \"\$t\" >/dev/null; done; true"
  log "RESULT image PASS $bt $et"
}

pytest_summary() { # STEP: last pytest summary line of its log
  grep -E '^(=+ )?[0-9]+ (passed|failed|skipped|error|deselected)' "$LOGS/$1.log" | tail -n 1 | tr -d '='
}

step_pytest() { # unit|disks|e2e [PYTEST_ARGS...]
  local step="$1"; shift
  if run_container "$step" "$@"; then log "RESULT $step PASS $(pytest_summary "$step")"
  else log "RESULT $step FAIL $(pytest_summary "$step") (see $LOGS/$step.log)"; grep -E '^FAILED|^ERROR' "$LOGS/$step.log" | head -n 20 >&2 || true; return 1; fi
}

step_inner() { # helper|fixtures|signflow|sbom|sbomcheck|vulnscan|kernelvex|lock: inside.sh prints its own RESULT line
  local step="$1"; shift
  local rc=0
  run_container "$step" "$@" || rc=$?
  grep -h 'RESULT' "$LOGS/$step.log" >&2 || log "RESULT $step FAIL exit $rc (see $LOGS/$step.log)"
  return "$rc"
}

step_status() {
  rr "docker ps -a --filter name=^beast-disks- --format '{{.Names}} {{.Status}}'; docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep '^beast-disks-' || true; du -sh '$R' '$R/cache/disk-fixtures' 2>/dev/null || echo 'no $R'"
}

step_clean() {
  rr "ids=\$(docker ps -aq --filter name=^beast-disks-); [ -z \"\$ids\" ] || docker rm -f \$ids >/dev/null
      imgs=\$(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^beast-disks-' || true); [ -z \"\$imgs\" ] || docker rmi \$imgs >/dev/null
      if [ -f '$R/state/pulled-base' ]; then
        base=\$(docker image inspect -f '{{.Id}}' '$BASE_REF' 2>/dev/null || true)
        # layers of interrupted builds: dangling images on top of the base we pulled (no one else had it)
        for i in \$(docker images -aq --no-trunc -f dangling=true); do
          [ -n \"\$base\" ] && docker history -q --no-trunc \"\$i\" 2>/dev/null | grep -qx \"\$base\" && docker rmi \"\$i\" >/dev/null 2>&1
        done
        docker rmi '$BASE_REF' >/dev/null 2>&1
      fi; true"
  if [ "$YES" = 1 ]; then
    rr "rm -rf '$R'"
  else
    rr "[ -d '$R' ] && find '$R' -mindepth 1 -maxdepth 1 ! -name cache -exec rm -rf {} + ; \
        [ -d '$R/cache' ] && find '$R/cache' -mindepth 1 -maxdepth 1 ! -name disk-fixtures -exec rm -rf {} + ; true"
  fi
  log "RESULT clean PASS ($( [ "$YES" = 1 ] && echo 'everything removed' || echo "fixture cache kept in $R/cache/disk-fixtures"))"
  step_status
}

main() {
  local step="" ; local -a pyargs=()
  while (($#)); do
    case "$1" in
      --host) HOST="$2"; shift 2 ;;
      --cpus) CPUS="$2"; shift 2 ;;
      --mem) MEM="$2"; shift 2 ;;
      --yes) YES=1; shift ;;
      --build-arg) BUILD_ARGS+=("$2"); shift 2 ;;
      -h|--help) usage ;;
      --) shift; pyargs=("$@"); break ;;
      -*) die "unknown option $1" ;;
      *) if [ -z "$step" ]; then step="$1"; else die "one step only"; fi; shift ;;
    esac
  done
  [ -n "$step" ] || usage 2
  [ -n "$HOST" ] || die "no test server: pass --host H or set BB_E2E_HOST (an ssh host name)"
  [[ "$CPUS" =~ ^[0-9]+$ ]] && [ "$CPUS" -ge 1 ] && [ "$CPUS" -le 6 ] || die "--cpus must be 1..6"
  [[ "$MEM" =~ ^[0-9]+$ ]] && [ "$MEM" -ge 2 ] && [ "$MEM" -le 12 ] || die "--mem must be 2..12 (GB)"
  init_remote
  case "$step" in
    sync|image|status|clean) "step_$step" ;;
    unit|disks|e2e) step_pytest "$step" "${pyargs[@]}" ;;
    helper|fixtures|signflow|sbom|sbomcheck) step_inner "$step" "${pyargs[@]}" ;;
    vulnscan|kernelvex)
      local rc=0 f
      step_inner "$step" "${pyargs[@]}" || rc=$?
      mkdir -p "$LOGS/vulns"
      for f in vulnerabilities.json VULNERABILITIES.md vex.proposed.openvex.json validation.json; do
        fetch "$R/out/vulns/$f" "$LOGS/vulns/$f" || true
      done
      if [ "$step" = kernelvex ] && [ "$rc" = 0 ]; then
        fetch "$R/out/vulns/kernel-vex-report.json" "$LOGS/vulns/kernel-vex-report.json" || true
        fetch "$R/out/vulns/vex.kernel.openvex.json" "$ROOT/sbom/vex.kernel.openvex.json" || rc=1
        log "sbom/vex.kernel.openvex.json copied back"
      fi
      return "$rc" ;;
    lock)
      step_inner lock
      fetch "$R/src/BeastBoot/build/beastnet/packages.lock" "$ROOT/build/beastnet/packages.lock"
      log "packages.lock copied back to build/beastnet/" ;;
    all)
      local s fails=()
      step_sync || fails+=(sync)
      step_image || fails+=(image)
      for s in unit helper fixtures disks; do
        case "$s" in unit|disks) step_pytest "$s" || fails+=("$s") ;; *) step_inner "$s" || fails+=("$s") ;; esac
      done
      if [ "${#fails[@]}" = 0 ]; then log "ALL PASS"; else log "ALL FAIL: ${fails[*]}"; return 1; fi ;;
    *) die "unknown step $step (see --help)" ;;
  esac
}

main "$@"
