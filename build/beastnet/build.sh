#!/usr/bin/env bash
# beast-booter: build beast-net, the helper Linux environment that downloads an
# ISO from a link (docs/BEASTNET.md). Rootless, idempotent, offline once the
# caches are warm.
#
#   build/beastnet/build.sh OUT_DIR
#
# Writes (and nothing else):
#   OUT_DIR/beast-net/vmlinuz        Ubuntu's Canonical-signed kernel, byte-identical to the .deb
#   OUT_DIR/beast-net/initrd.img     xz newc cpio (mkinitrd.py): module subset, busybox, kmod,
#                                    wpa_supplicant, iw, Python 3.14, CA bundle, the beastnet app
#   OUT_DIR/beast-net/VERSION        "beast-net <VERSION> kernel <kver>"
#   OUT_DIR/beast-net/catalog.json   firmware pack catalog (gen_catalog.py)
#   OUT_DIR/beast-net.origins.json   {"beast-net/<file>": "<origin>"} for dist/manifest.json
#   OUT_DIR/beast-net.contents.json  every file inside initrd.img with origin + SHA-256, the
#                                    package list and the firmware report (not for the ESP)
#
# Inputs: build/beastnet/{packages.lock,userland.list,modules.list,firmware.lock},
# beastnet/ (the app: rootfs/ + python/beastnet/ [+ runtime.json]).
#
# Environment:
#   SOURCE_DATE_EPOCH   mtime of everything (default: last git commit time, else mtime of VERSION,
#                       exactly like build/build.sh)
#   BB_BEASTNET_CACHE   .deb cache            (default: .tools/cache/beastnet)
#   BB_FIRMWARE_CACHE   linux-firmware cache  (default: .tools/cache/linux-firmware)
#   BB_BEASTNET_APP     app directory         (default: $BB_ROOT/beastnet)
#   BB_BEASTNET_NO_APP=1  build without the app (pipeline tests only; the initrd then has no /init)
#   BB_OFFLINE=1        fail instead of downloading anything
#   BB_BEASTNET_REVERIFY=1  download every firmware file of the catalog from kernel.org
#                       again and compare its SHA-256 (release check; needs network)
#   BB_SHIM_DIR         shim-signed directory: the kernel is verified against the Canonical CA
#                       embedded in that shim (set by scripts/dev-env.sh)
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BB_ROOT="${BB_ROOT:-$(cd "$HERE/../.." && pwd)}"
if [ -z "${BB_SHIM_DIR:-}" ] && [ -f "$BB_ROOT/scripts/dev-env.sh" ]; then
  # shellcheck source=/dev/null
  source "$BB_ROOT/scripts/dev-env.sh"
fi

log()  { echo "beastnet: $*"; }
warn() { echo "beastnet: WARNING: $*" >&2; }
die()  { echo "beastnet: error: $*" >&2; exit 1; }
py()   { python3 -I "$@"; }

[ $# -eq 1 ] || die "usage: $0 OUT_DIR"
for t in python3 dpkg-deb tar sha256sum sbverify objcopy openssl; do
  command -v "$t" >/dev/null || die "required tool not found: $t"
done
py -c 'import lzma, sys; sys.exit(sys.version_info < (3, 10))' || die "python3 >= 3.10 with lzma required"

VERSION="$(tr -d ' \t\r\n' < "$BB_ROOT/VERSION")"
[[ "$VERSION" =~ ^[0-9][0-9A-Za-z.+~-]*$ ]] || die "VERSION has an unexpected format: '$VERSION'"
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  SDE_FROM="SOURCE_DATE_EPOCH"
elif SOURCE_DATE_EPOCH="$(git -C "$BB_ROOT" log -1 --format=%ct 2>/dev/null)" && [ -n "$SOURCE_DATE_EPOCH" ]; then
  SDE_FROM="last git commit"
else
  SOURCE_DATE_EPOCH="$(stat -c %Y "$BB_ROOT/VERSION")"; SDE_FROM="mtime of VERSION"
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be an integer"
export SOURCE_DATE_EPOCH

CACHE="${BB_BEASTNET_CACHE:-$BB_ROOT/.tools/cache/beastnet}"
FWCACHE="${BB_FIRMWARE_CACHE:-$BB_ROOT/.tools/cache/linux-firmware}"
DEBS="$CACHE/debs"
APP="${BB_BEASTNET_APP:-$BB_ROOT/beastnet}"
mkdir -p "$1"
OUT="$(cd "$1" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/beastnet.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
log "beast-net $VERSION, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($SDE_FROM)"

# ---------------------------------------------------------------------------
# Packages: every .deb of packages.lock, SHA-256-checked
# ---------------------------------------------------------------------------
py "$HERE/lock.py" --fetch --cache "$CACHE" --lock "$HERE/packages.lock"
read -r KPKG KVERSION KARCH _ < <(awk '!/^#/ && $5 == "kernel" {print $1, $2, $3, $4}' "$HERE/packages.lock")
[ -n "${KPKG:-}" ] || die "packages.lock has no kernel package"
KVER="${KPKG#linux-image-}"
KDEB="$DEBS/${KPKG}_${KVERSION//:/%3a}_${KARCH}.deb"

# ---------------------------------------------------------------------------
# vmlinuz: unmodified, Canonical-signed, chains to the CA in the shim we ship
# ---------------------------------------------------------------------------
VMLINUZ_PATH="/boot/vmlinuz-$KVER"
mkdir -p "$WORK/out/beast-net"
dpkg-deb --fsys-tarfile "$KDEB" | tar -xO ".$VMLINUZ_PATH" > "$WORK/out/beast-net/vmlinuz"
want="$(dpkg-deb -I "$KDEB" md5sums | awk -v p="${VMLINUZ_PATH#/}" '$2 == p {print $1}')"
[ -n "$want" ] && [ "$(md5sum < "$WORK/out/beast-net/vmlinuz" | cut -d' ' -f1)" = "$want" ] \
  || die "$VMLINUZ_PATH does not match the md5sums of $KPKG"
sigs="$(sbverify --list "$WORK/out/beast-net/vmlinuz" 2>/dev/null)" || true
[ "$(grep -c '^signature [0-9]' <<<"$sigs")" -ge 1 ] || die "vmlinuz is not signed"
KSIGNER="$(sed -n 's/^ - subject: .*CN=//p' <<<"$sigs" | head -n1)"
grep -q 'issuer: .*O=Canonical Ltd\./CN=Canonical Ltd\. Master Certificate Authority' <<<"$sigs" \
  || die "vmlinuz is not signed by a Canonical Ltd. Master Certificate Authority certificate"
SHIM="${BB_SHIM_DIR:-/usr/lib/shim}/shimx64.efi.signed.latest"
KCHECK="signer CN=$KSIGNER"
if [ -f "$SHIM" ]; then
  # The Canonical CA that shim trusts (its .vendor_cert section) must verify the kernel.
  objcopy -O binary --only-section=.vendor_cert "$SHIM" "$WORK/vendor_cert.raw"
  py - "$WORK/vendor_cert.raw" "$WORK/vendor.der" <<'EOF'
import struct, sys
d = open(sys.argv[1], "rb").read()
size, _dsize, off, _doff = struct.unpack_from("<IIII", d, 0)
open(sys.argv[2], "wb").write(d[off:off + size])
EOF
  openssl x509 -inform DER -in "$WORK/vendor.der" -out "$WORK/vendor.pem" 2>/dev/null \
    || die "$SHIM: .vendor_cert is not a single X.509 certificate"
  vsubj="$(openssl x509 -in "$WORK/vendor.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
  sbverify --cert "$WORK/vendor.pem" "$WORK/out/beast-net/vmlinuz" >/dev/null 2>&1 \
    || die "vmlinuz does not verify against the vendor certificate of $SHIM ($vsubj)"
  KCHECK="$KCHECK; verifies against shim's vendor cert $vsubj"
  if [ -x "${BB_SHIM_DIR:-/usr/lib/shim}/is-not-revoked" ]; then
    "${BB_SHIM_DIR:-/usr/lib/shim}/is-not-revoked" "$WORK/out/beast-net/vmlinuz" 2>"$WORK/revoked.log" \
      || { cat "$WORK/revoked.log" >&2; die "vmlinuz is signed with a revoked Canonical key"; }
    KCHECK="$KCHECK; not revoked (shim-signed is-not-revoked)"
  fi
else
  warn "$SHIM not found: kernel signature checked by issuer name only"
fi
log "vmlinuz: $KPKG=$KVERSION, $KCHECK"

# ---------------------------------------------------------------------------
# initrd.img
# ---------------------------------------------------------------------------
APP_ARGS=()
if [ "${BB_BEASTNET_NO_APP:-0}" = 1 ]; then
  warn "building WITHOUT the beastnet app (BB_BEASTNET_NO_APP=1): the initrd has no /init"
else
  [ -f "$APP/rootfs/init" ] && [ -f "$APP/python/beastnet/__init__.py" ] \
    || die "the beastnet app is missing ($APP/rootfs/init, $APP/python/beastnet/); BB_BEASTNET_NO_APP=1 builds without it"
  APP_ARGS=(--app "$APP")
fi
py "$HERE/mkinitrd.py" --lock "$HERE/packages.lock" --debs "$DEBS" \
  --userland "$HERE/userland.list" --modules "$HERE/modules.list" "${APP_ARGS[@]}" \
  --sde "$SOURCE_DATE_EPOCH" --work "$WORK" --stage "$WORK/stage" \
  --out-initrd "$WORK/out/beast-net/initrd.img" --out-contents "$WORK/contents.json" \
  --out-info "$WORK/info.json"

# ---------------------------------------------------------------------------
# catalog.json
# ---------------------------------------------------------------------------
FW_ARGS=()
[ "${BB_OFFLINE:-0}" = 1 ] && FW_ARGS+=(--offline)
[ "${BB_BEASTNET_REVERIFY:-0}" = 1 ] && FW_ARGS+=(--reverify)
py "$HERE/gen_catalog.py" --stage "$WORK/stage" --info "$WORK/info.json" \
  --lock "$HERE/firmware.lock" --cache "$FWCACHE" \
  --out "$WORK/out/beast-net/catalog.json" --report "$WORK/firmware-report.json" "${FW_ARGS[@]}"

printf 'beast-net %s kernel %s\n' "$VERSION" "$KVER" > "$WORK/out/beast-net/VERSION"

# ---------------------------------------------------------------------------
# origins + contents
# ---------------------------------------------------------------------------
APP_DESC="no app (BB_BEASTNET_NO_APP=1)"
[ "${#APP_ARGS[@]}" -gt 0 ] && APP_DESC="repo:${APP#"$BB_ROOT"/}/rootfs + repo:${APP#"$BB_ROOT"/}/python/beastnet"
py - "$WORK" "$KPKG=$KVERSION" "$VMLINUZ_PATH" "$APP_DESC" "$KCHECK" <<'EOF'
import json, os, sys
work, kkey, vpath, app, kcheck = sys.argv[1:]
info = json.load(open(os.path.join(work, "info.json")))
contents = json.load(open(os.path.join(work, "contents.json")))
cat = json.load(open(os.path.join(work, "out/beast-net/catalog.json")))
report = json.load(open(os.path.join(work, "firmware-report.json")))
pkgs = ", ".join("deb:" + p for p in info["packages"])
origins = {
    "beast-net/vmlinuz": f"deb:{kkey}:{vpath}",
    "beast-net/initrd.img": (
        "built:build/beastnet/build.sh (newc cpio, xz) from " + pkgs
        + f"; {len(info['modules'])} modules of deb:{info['modules_pkg']} + depmod"
        + f"; {app}; CA bundle from ca-certificates; userland.list + modules.list"),
    "beast-net/VERSION": "built:build/beastnet/build.sh",
    "beast-net/catalog.json": (
        f"built:build/beastnet/gen_catalog.py from modinfo of the bundled modules (deb:{info['modules_pkg']})"
        f" + linux-firmware {cat['source']['tag']} ({report['commit']})"),
}
with open(os.path.join(work, "out/beast-net.origins.json"), "w") as f:
    json.dump(origins, f, indent=1, sort_keys=True)
    f.write("\n")
contents["vmlinuz"] = {"origin": origins["beast-net/vmlinuz"], "checks": kcheck}
contents["firmware"] = report
with open(os.path.join(work, "out/beast-net.contents.json"), "w") as f:
    json.dump(contents, f, indent=1)
    f.write("\n")
EOF

# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
find "$WORK/out" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
chmod 0755 "$WORK/out/beast-net"; chmod 0644 "$WORK/out/beast-net/"* "$WORK/out/"*.json
NEW="$(mktemp -d "$OUT/.beast-net.new.XXXXXX")"
mv "$WORK/out/beast-net" "$NEW/beast-net"
if [ -e "$OUT/beast-net" ]; then
  OLD="$(mktemp -d "$OUT/.beast-net.old.XXXXXX")"
  mv "$OUT/beast-net" "$OLD/"
  mv "$NEW/beast-net" "$OUT/beast-net"
  rm -rf "$OLD"
else
  mv "$NEW/beast-net" "$OUT/beast-net"
fi
rmdir "$NEW"
mv -f "$WORK/out/beast-net.origins.json" "$WORK/out/beast-net.contents.json" "$OUT/"

total=0
for f in vmlinuz initrd.img VERSION catalog.json; do
  s="$(stat -c %s "$OUT/beast-net/$f")"; total=$((total + s))
  printf 'beastnet:   %-14s %10d bytes  %s\n' "$f" "$s" "$(sha256sum < "$OUT/beast-net/$f" | cut -d' ' -f1)"
done
log "wrote $OUT/beast-net ($((total / 1048576)) MiB) + beast-net.origins.json + beast-net.contents.json"
