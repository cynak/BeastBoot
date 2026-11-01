#!/usr/bin/env bash
# Run a command in the Linux build environment (build/Containerfile: x86-64 Ubuntu).
#
#   scripts/container.sh CMD [ARGS...]    e.g. scripts/container.sh ./build/build.sh
#   scripts/container.sh --image          only build (or refresh) the image
#   scripts/container.sh --shell          an interactive shell inside it
#
# CMD runs at the repo root with scripts/dev-env.sh sourced; its exit status is
# passed through. The repo is mounted at the same absolute path, so host paths
# work inside. .tools/ inside is a docker volume (the host's may hold another
# OS's binaries), seeded on first use with the GRUB build the image made.
# On Linux CMD runs directly on the host unless BB_CONTAINER=1.
#
# Environment: BB_CONTAINER_CLI (docker | podman), BB_CONTAINER_IMAGE (default
# beast-boot-build), BB_CONTAINER_VOLUME (default beast-boot-tools). Variables
# named BB_* (except paths dev-env.sh picks) and SOURCE_DATE_EPOCH are passed in.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/platform.sh
source "$ROOT/scripts/lib/platform.sh"

IMAGE="${BB_CONTAINER_IMAGE:-beast-boot-build}"
VOLUME="${BB_CONTAINER_VOLUME:-beast-boot-tools}"
PLATFORM=linux/amd64
CONTAINERFILE="$ROOT/build/Containerfile"
BASE_IMAGE="$(sed -n 's/^FROM //p' "$CONTAINERFILE" | head -n1)"
LABEL=org.beast-boot.containerfile-sha256

log() { echo "container: $*" >&2; }
die() { echo "container: error: $*" >&2; exit 1; }

pick_cli() {
  local c
  for c in ${BB_CONTAINER_CLI:-} docker podman; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  die "no container runtime found. On macOS: brew install colima docker docker-buildx, then
       colima start --vm-type vz --vz-rosetta   (or install podman)"
}

ensure_engine() {
  "$CLI" info >/dev/null 2>&1 && return 0
  if [ "$CLI" = docker ] && command -v colima >/dev/null 2>&1; then
    log "starting Colima"
    colima start --vm-type vz --vz-rosetta=false >&2 || die "colima start failed (see above)"
    "$CLI" info >/dev/null 2>&1 && return 0
  fi
  die "$CLI is installed but its engine is not running (colima start / podman machine start)"
}

# Ubuntu 26.04's tar needs openat2(), which Rosetta and QEMU < 9.1 lack: every
# extraction then fails with "Cannot open: Function not implemented".
ensure_emulator() {
  [ "$(uname -m)" = x86_64 ] && return 0
  "$CLI" run --rm --platform "$PLATFORM" "${BASE_IMAGE}" sh -c \
    'cd /tmp && mkdir a && : > a/f && tar cf t.tar a && mkdir o && tar -C o -xf t.tar' >/dev/null 2>&1 && return 0
  die "the x86-64 emulator in the container VM is too old for Ubuntu 26.04 (no openat2).
       Turn Rosetta off (colima stop; colima start --vm-type vz --vz-rosetta=false), then
       register a current QEMU (needs to be redone after each VM restart):
         $CLI run --privileged --rm tonistiigi/binfmt --install amd64"
}

# The image only provides the toolchain; it is rebuilt when build/Containerfile changes.
ensure_image() {
  local want have
  want="$(bb_sha256 "$CONTAINERFILE")"
  have="$("$CLI" image inspect --format "{{ index .Config.Labels \"$LABEL\" }}" "$IMAGE" 2>/dev/null || true)"
  if [ "$have" = "$want" ] && [ "${1:-}" != force ]; then return 0; fi
  ensure_emulator
  log "building image $IMAGE ($PLATFORM; the first time takes a while: it builds GRUB)"
  "$CLI" build --platform "$PLATFORM" --label "$LABEL=$want" -t "$IMAGE" -f "$CONTAINERFILE" "$ROOT" >&2
}

ensure_volume() {
  "$CLI" volume inspect "$VOLUME" >/dev/null 2>&1 && return 0
  "$CLI" volume create "$VOLUME" >/dev/null
  log "seeding volume $VOLUME (.tools inside the container) from the image"
  "$CLI" run --rm --platform "$PLATFORM" -v "$VOLUME:/seed" "$IMAGE" cp -a /src/.tools/. /seed/
}

env_args() {
  local name
  while IFS='=' read -r name _; do
    case "$name" in
      BB_ROOT|BB_PYTHON|BB_CONTAINER*|BB_*_DIR) ;;
      BB_*|SOURCE_DATE_EPOCH) printf '%s\n' "-e" "$name" ;;
    esac
  done < <(env)
}

run_in_container() {
  local tty=() envs=()
  [ -t 0 ] && tty+=(-i)
  [ -t 1 ] && tty+=(-t)
  mapfile -t envs < <(env_args)
  # git refuses a repository owned by another user; the mount looks that way to root
  "$CLI" run --rm --init --platform "$PLATFORM" "${tty[@]}" \
    -v "$ROOT:$ROOT" -v "$VOLUME:$ROOT/.tools" -w "$ROOT" \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    "${envs[@]}" \
    "$IMAGE" bash -c 'source scripts/dev-env.sh && exec "$@"' bash "$@"
}

main() {
  [ "$#" -gt 0 ] || die "usage: scripts/container.sh CMD [ARGS...] | --image | --shell"
  if [ "$(bb_os)" = linux ] && [ "${BB_CONTAINER:-0}" != 1 ] && [ "$1" != --image ] && [ "$1" != --shell ]; then
    cd "$ROOT"
    # shellcheck source=dev-env.sh
    source "$ROOT/scripts/dev-env.sh"
    exec "$@"
  fi
  CLI="$(pick_cli)"
  ensure_engine
  case "$1" in
    --image) ensure_image force; ensure_volume; return 0 ;;
    --shell) set -- bash ;;
  esac
  ensure_image
  ensure_volume
  run_in_container "$@"
}

bb_require_bash4 "$0" "$@"
main "$@"
