#!/usr/bin/env bash
# Regenerate the README screenshots in docs/assets/screenshots/.
#
#   scripts/make_screenshots.sh [app|menu|all]     (default: all)
#
#   app   the desktop app with simulated drives (scripts/screenshots/app_screens.py),
#         in a container (podman or docker) that has Tk, Xvfb and fonts, so no
#         window opens on your desktop. Nothing is written to any drive.
#   menu  the boot menu: a small drive image (bb-dev image) whose data partition
#         holds tiny stand-in ISOs with real distribution names (the e2e fixture
#         ISOs, copied), booted in QEMU (bb-dev vm, UEFI); the pictures are taken
#         with the QEMU monitor's screendump and the keys are sent with sendkey.
#
# Needs dist/ (make build), and for "menu" the bb-dev toolchain (make tools).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/docs/assets/screenshots"
WORK="$ROOT/out/screenshots"
what="${1:-all}"
case "$what" in app|menu|all) ;; *) echo "usage: $0 [app|menu|all]" >&2; exit 2 ;; esac
log() { echo "screenshots: $*"; }
die() { echo "screenshots: error: $*" >&2; exit 1; }
[ -f "$ROOT/dist/manifest.json" ] || die "dist/ is missing: run make build first"
mkdir -p "$OUT" "$WORK"

# The window shows the Secure Boot key's fingerprints. The pictures must not show
# a real key (yours, or one a reader could mistake for the release key), so the
# app reads a copy of the boot-file metadata with a throwaway example certificate.
example_dist() {
  local d="$1" cer
  rm -rf "$d"; mkdir -p "$d/esp/beast-net"
  cer="$d/esp/ENROLL_THIS_KEY_IN_MOKMANAGER.cer"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -days 3650 -outform DER -out "$cer" \
    -subj "/CN=beast-boot Secure Boot key (example)" 2>/dev/null
  cp "$ROOT/dist/esp/beast-net/catalog.json" "$d/esp/beast-net/"
  python3 -I - "$ROOT/dist/manifest.json" "$d/manifest.json" "$cer" <<'PY2'
import hashlib, json, sys
m = json.load(open(sys.argv[1]))
der = open(sys.argv[3], "rb").read()
m["secure_boot"].update(cert_subject="CN=beast-boot Secure Boot key (example)",
                        cert_sha1=hashlib.sha1(der).hexdigest(), cert_sha256=hashlib.sha256(der).hexdigest())
json.dump(m, open(sys.argv[2], "w"), indent=1)
PY2
}

app_shots() {
  local engine version pkg
  engine="$(command -v podman || command -v docker || true)"
  [ -n "$engine" ] || die "the app screenshots need podman or docker"
  version="$(tr -d '[:space:]' < "$ROOT/VERSION")"
  pkg="/home/you/beast-boot-$version-linux-x86_64"
  example_dist "$WORK/app-dist"
  log "building the screenshot container with $(basename "$engine")"
  "$engine" build -q -t beast-boot-screenshots -f "$ROOT/scripts/screenshots/Containerfile" \
    "$ROOT/scripts/screenshots" >/dev/null
  log "taking the app screenshots"
  # shellcheck disable=SC2016 # the sh -c script is expanded inside the container
  "$engine" run --rm --network none \
    -v "$ROOT/installer:/src/installer:ro" -v "$ROOT/VERSION:/src/VERSION:ro" \
    -v "$WORK/app-dist:$pkg/payload/dist:ro" \
    -v "$ROOT/scripts/screenshots:/src/shots:ro" -v "$OUT:/out" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -e PKG_DIST="$pkg/payload/dist" \
    beast-boot-screenshots sh -c '
      xvfb-run -a -s "-screen 0 1920x1200x24 -dpi 96" \
        python3 -B /src/shots/app_screens.py /src/installer "$PKG_DIST" /out
      rc=$?; chown "$HOST_UID:$HOST_GID" /out/app-*.png 2>/dev/null; exit $rc'
}

# -- boot menu --------------------------------------------------------------
MENU_TREE=(
  "Linux/archlinux-2026.10.01-x86_64.iso:archiso"
  "Linux/debian-13.7.0-amd64-netinst.iso:none"
  "Linux/kubuntu-26.04.1-desktop-amd64.iso:loopback"
  "Linux/openSUSE-Tumbleweed-DVD-x86_64-Current.iso:suse"
  "Rescue/gparted-live-1.7.0-1-amd64.iso:live-boot"
  "Rescue/systemrescue-12.02-amd64.iso:archiso"
  "Fedora-Workstation-Live-44-1.7.x86_64.iso:dracut-live"
  "debian-live-13.7.0-amd64-gnome.iso:live-boot"
  "linuxmint-22.2-cinnamon-64bit.iso:casper"
  "ubuntu-26.04.1-desktop-amd64.iso:loopback"
)
MON="$ROOT/out/vm/screenshots/monitor.sock"
SOCAT="$(command -v socat || echo "$ROOT/.tools/bin/socat")"
hmp() { printf '%s\n' "$*" | "$SOCAT" - "UNIX-CONNECT:$MON" >/dev/null 2>&1 || true; }
keys() { local k; for k in "$@"; do hmp "sendkey $k"; sleep 0.25; done; }
grab() { sleep "${2:-2}"; hmp "screendump $OUT/$1.png -f png"; sleep 1; log "$1.png"; }

menu_shots() {
  local fixtures="$ROOT/out/e2e/fixtures" isos="$WORK/isos" img="$WORK/screenshots.img" entry
  log "building the fixture ISOs"
  python3 -I "$ROOT/tests/e2e/fixtures/build_fixtures.py" --out "$fixtures" >/dev/null
  rm -rf "$isos"; mkdir -p "$isos"
  for entry in "${MENU_TREE[@]}"; do
    mkdir -p "$isos/$(dirname "${entry%%:*}")"
    cp "$fixtures/${entry##*:}.iso" "$isos/${entry%%:*}"
  done
  log "building the drive image"
  "$ROOT/bin/bb-dev" image --out "$img" --size 2G --fs exfat --isos "$isos" --force -y >/dev/null
  log "booting it in QEMU (UEFI, with a network card for the download helper)"
  rm -f "$MON"
  "$ROOT/bin/bb-dev" vm --image "$img" --mode uefi --display none --serial file --mem 2048 \
    --refresh never --snapshot -- -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile= \
    >"$WORK/vm.log" 2>&1 &
  local vm=$!
  trap 'hmp quit; wait "$vm" 2>/dev/null || true' RETURN
  for _ in $(seq 1 60); do [ -S "$MON" ] && break; sleep 0.5; done
  [ -S "$MON" ] || die "QEMU did not start (see $WORK/vm.log)"
  # Root menu: Linux/, Rescue/, 4 ISOs, then System information, Download, ...
  grab menu-root 12
  keys ret;                 grab menu-folder 3      # into Linux/
  keys esc;                 sleep 2
  keys down down down down down down ret; grab menu-system 4
  keys esc;                 sleep 2
  keys down down down down down down down ret; grab menu-download 45
}

case "$what" in
  app) app_shots ;;
  menu) menu_shots ;;
  all) app_shots; menu_shots ;;
esac
log "done: $(find "$OUT" -maxdepth 1 -name '*.png' -printf '%f\n' | sort | tr '\n' ' ')"
