#!/usr/bin/env bash
# Purpose: one step of devtools/e2e-on-kvm-host.sh, run INSIDE the unprivileged beast-disks-env
#          container (only /dev/kvm from the host; the work dir ~/vms/beast-disks is mounted at /w).
# Usage:   inside.sh unit|helper|fixtures|disks|e2e|signflow|sbom|sbomcheck|vulnscan|kernelvex|lock [PYTEST_ARGS...]
#   unit      beastnet/tests (venv from requirements-dev.txt)
#   helper    throw-away test key + build/build.sh into /w/dist; checks the helper app is in initrd.img and no add-on is
#   fixtures  disk fixtures built in a throw-away Ubuntu cloud-image guest (KVM, user-mode NAT); the
#             guest's own kernel does the loop/md/LVM/dm work, the image cache is copied out to /w/cache
#   lock      build/beastnet/lock.py: regenerate packages.lock after packages.in changed
#   disks     tests/e2e/test_e2e_disks.py and test_e2e_disks_copy.py against /w/dist and the fixture cache
#   e2e       pytest on the given files and options against /w/dist (QEMU with KVM: BIOS, UEFI, Secure
#             Boot); without arguments tests/e2e except the two Disk tools files
#   signflow  the release's signing split by hand (docs/RELEASING.md "Signing in its own job"): build
#             unsigned with one throw-away key set, build/sign.sh with the three leaves of a second CA
#             (whose key is elsewhere), rebuild twice without a private key (BB_PRESIGNED_DIR): the two
#             must be byte-identical and pass verify-dist.sh. Then the negatives (a file signed with
#             another component's leaf, leaves of another CA) and a replaced leaf
#   sbom      build/verify-dist.sh on /w/dist (arguments go to it, e.g. --rebuild: GRUB, wimboot and
#             beastmount.exe from source again, compared byte for byte), then scripts/gen_sbom.py from it
#             into /w/out/sbom (no scan): fails on a failed check or a provenance error
#   sbomcheck scripts/install-tools.sh (downloads the pinned SBOM tools and schemas), scripts/sbom-vuln.sh
#             sbom (gen_sbom.py and validate_sbom.py, into the source copy's sbom/) and scripts/selftest.py
#   vulnscan  scripts/install-tools.sh, scripts/sbom-vuln.sh sbom and scripts/sbom-vuln.sh scan (grype and
#             osv-scanner with the OpenVEX triage of sbom/, and the boot-chain checks: SBAT, signers, dbx)
#             on /w/dist; arguments go to the scan (e.g. --fail-on critical). Downloads the vulnerability
#             databases into /w/tools/cache. The reports are copied to /w/out/vulns
#   kernelvex after a kernel update (sbom/README.md "Kernel CVEs"): the scan, scripts/kernel_vex.py
#             (kernel.org CVE records, Ubuntu's kernel source and CVE tracker: large downloads into
#             /w/tools/cache/kernel-vex), the scan again with the new statements. The new
#             sbom/vex.kernel.openvex.json and kernel-vex-report.json are copied to /w/out/vulns
set -euo pipefail

W=/w
REPO="$W/src/BeastBoot"
LOGS="$W/logs"
VENV="$W/venv"
CLOUD_URL="https://cloud-images.ubuntu.com/resolute/current"
CLOUD_IMG="resolute-server-cloudimg-amd64.img"
GUEST_CPUS="${GUEST_CPUS:-4}"
GUEST_MEM="${GUEST_MEM:-6144}"
APP_MODULES="beastnet/__main__.py beastnet/app.py beastnet/addons.py beastnet/diskflow.py"

export HOME="$W/home" BB_KEY_DIR="$W/keys" BB_DIST_DIR="$W/dist" BB_E2E_DIST="$W/dist" \
  BB_E2E_OUT="$W/out/e2e" BB_DISK_FIXTURE_CACHE="$W/cache/disk-fixtures" BB_E2E_KVM=1

log() { printf '[inside %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { log "error: $*" >&2; exit 1; }

setup() {
  mkdir -p "$HOME" "$LOGS" "$W/tools" "$BB_DISK_FIXTURE_CACHE" "$W/out"
  # .tools: GRUB built from source and Debian's shim from the build image, seeded by the driver
  # (seed_tools; scripts/container.sh seeds its volume the same way)
  [ -d "$W/tools/cache/grub-src" ] || die "$W/tools is not seeded"
  [ -e "$REPO/.tools" ] || ln -s "$W/tools" "$REPO/.tools"
  cd "$REPO"
  # shellcheck source=/dev/null
  source scripts/dev-env.sh
}

venv() {
  local want have
  want="$(sha256sum requirements-dev.txt | cut -c1-16)"
  have="$(cat "$VENV/.req" 2>/dev/null || true)"
  if [ "$want" != "$have" ]; then
    rm -rf "${VENV:?}"
    python3 -m venv --system-site-packages "$VENV"
    "$VENV/bin/pip" install -q --require-hashes -r requirements-dev.txt
    echo "$want" > "$VENV/.req"
  fi
}

step_unit() {
  venv
  log "python $("$VENV/bin/python" -V 2>&1), pytest $("$VENV/bin/python" -m pytest --version 2>&1)"
  nice -n 10 "$VENV/bin/python" -m pytest -q -p no:cacheprovider -rfE --tb=line \
    --junitxml="$LOGS/unit.xml" beastnet/tests "$@"
}

step_helper() {
  [ -f "$BB_KEY_DIR/beast-boot-grub.key" ] || { log "creating throw-away test keys (a CA and three leaves) in $BB_KEY_DIR"; build/keygen.sh; }
  log "build/build.sh -> $BB_DIST_DIR (SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-unset})"
  nice -n 10 build/build.sh
  local initrd="$BB_DIST_DIR/esp/beast-net/initrd.img" missing=0 m names
  [ -f "$initrd" ] || die "no $initrd"
  names="$(python3 -I - "$initrd" <<'EOF'
import sys
sys.path[:0] = ["tests/e2e"]
from bbe2e import disks
for n in sorted(disks.initrd_names(sys.argv[1])):
    print(n)
EOF
)"
  for m in $APP_MODULES; do
    if grep -q "dist-packages/$m\$" <<<"$names"; then log "initrd has $m"; else log "initrd LACKS $m"; missing=$((missing + 1)); fi
  done
  # BeastBoot ships no add-on (beastnet/README.md "Add-ons"): the directory must not be in its initrd
  if grep -q "usr/lib/beastnet/addons" <<<"$names"; then log "RESULT helper FAIL the initrd ships an add-on directory"; return 1; fi
  log "helper: $(cat "$BB_DIST_DIR/esp/beast-net/VERSION"), initrd $(du -h "$initrd" | cut -f1)"
  if [ "$missing" = 0 ]; then log "RESULT helper PASS app modules 4/4 in initrd, no add-on"
  else log "RESULT helper FAIL $missing app module(s) missing from initrd"; return 1; fi
}

ssh_guest() {
  ssh -q -p 2222 -i "$G/key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -o ServerAliveInterval=30 bb@127.0.0.1 "$@"
}

guest_stop() {
  [ -f "$G/qemu.pid" ] || return 0
  local pid; pid="$(cat "$G/qemu.pid")"
  ssh_guest 'sudo systemctl poweroff' >/dev/null 2>&1 || true
  for _ in $(seq 60); do kill -0 "$pid" 2>/dev/null || break; sleep 2; done
  kill "$pid" 2>/dev/null || true
  rm -f "$G/qemu.pid"
}

guest_start() {
  local img="$W/cache/cloudimg/$CLOUD_IMG" sum
  mkdir -p "$W/cache/cloudimg" "$G/seed"
  if [ ! -f "$img" ]; then
    log "downloading $CLOUD_IMG"
    curl -fsSL -o "$img.part" "$CLOUD_URL/$CLOUD_IMG"
    sum="$(curl -fsSL "$CLOUD_URL/SHA256SUMS" | awk -v f="*$CLOUD_IMG" '$2 == f {print $1}')"
    [ -n "$sum" ] && [ "$(sha256sum "$img.part" | cut -d' ' -f1)" = "$sum" ] || die "cloud image checksum mismatch"
    mv "$img.part" "$img"
  fi
  qemu-img create -q -f qcow2 -F qcow2 -b "$img" "$G/disk.qcow2" 40G
  ssh-keygen -q -t ed25519 -N '' -f "$G/key"
  printf 'instance-id: beast-disks-guest\nlocal-hostname: beast-disks-guest\n' > "$G/seed/meta-data"
  cat > "$G/seed/user-data" <<EOF
#cloud-config
users:
  - name: bb
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys: ["$(cat "$G/key.pub")"]
EOF
  xorriso -as mkisofs -quiet -o "$G/seed.iso" -V cidata -J -r "$G/seed"
  # user-mode NAT only; SSH is forwarded to 127.0.0.1 inside this container (no host port)
  qemu-system-x86_64 -name beast-disks-guest -machine q35,accel=kvm -cpu host -smp "$GUEST_CPUS" -m "$GUEST_MEM" \
    -drive "file=$G/disk.qcow2,if=virtio,discard=unmap" -cdrom "$G/seed.iso" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
    -display none -serial "file:$LOGS/fixtures-guest-console.log" -monitor none \
    -daemonize -pidfile "$G/qemu.pid"
  for _ in $(seq 90); do ssh_guest true 2>/dev/null && break; sleep 4; done
  ssh_guest true || die "guest SSH did not come up (see logs/fixtures-guest-console.log)"
  ssh_guest 'cloud-init status --wait >/dev/null 2>&1 || true; uname -r'
}

step_fixtures() {
  local dir hash t0 t1
  dir="$(python3 -I tests/e2e/fixtures/disks.py path)"
  hash="$(basename "$dir")"
  if [ -f "$dir/manifest.json" ]; then log "RESULT fixtures PASS cached $hash $(du -sh "$dir" | cut -f1) on disk"; return 0; fi
  G="$W/guest"
  rm -rf "${G:?}"; mkdir -p "$G"
  trap guest_stop EXIT
  log "booting the fixture guest (Ubuntu $CLOUD_IMG, KVM, $GUEST_CPUS CPUs, $GUEST_MEM MiB)"
  guest_start
  log "guest: installing docker.io"
  ssh_guest 'sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null'
  # the lvm-raid set needs dm-raid, which the cloud image kernel lacks (no linux-modules-extra for
  # its version in the archive): install the current linux-generic and reboot into it
  if ! ssh_guest 'modinfo dm-raid >/dev/null 2>&1'; then
    log "guest: no dm-raid in $(ssh_guest 'uname -r'); installing linux-generic and rebooting"
    ssh_guest 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-generic >/dev/null'
    ssh_guest 'sudo systemctl reboot' || true
    sleep 15
    for _ in $(seq 90); do ssh_guest 'modinfo dm-raid >/dev/null 2>&1' && break; sleep 4; done
    ssh_guest 'modinfo dm-raid >/dev/null 2>&1' || die "guest kernel $(ssh_guest 'uname -r' || true) has no dm-raid"
  fi
  # (the builder mounts the guest's /lib/modules and loads what it needs itself)
  log "guest kernel $(ssh_guest 'uname -r')"
  tar -C "$REPO" -cf - tests/e2e/fixtures/disks.py tests/e2e/fixtures/_disks_inside.py tests/e2e/fixtures/Dockerfile.disks \
    | ssh_guest 'rm -rf bb && mkdir -p bb && tar -xf - -C bb'
  t0="$(date +%s)"
  log "guest: tests/e2e/fixtures/disks.py build (its privileged docker run is inside the guest)"
  ssh_guest 'cd bb && sudo BB_DISK_FIXTURE_CACHE=/var/bbfx python3 tests/e2e/fixtures/disks.py build' \
    || die "fixture build failed in the guest"
  t1="$(date +%s)"
  ssh_guest "test -f /var/bbfx/$hash/manifest.json" || die "guest built another recipe hash than $hash"
  rm -rf "${BB_DISK_FIXTURE_CACHE:?}/.incoming"; mkdir -p "$BB_DISK_FIXTURE_CACHE/.incoming"
  ssh_guest "sudo tar -C /var/bbfx -cSf - $hash" | tar -C "$BB_DISK_FIXTURE_CACHE/.incoming" -xSf -
  mv "$BB_DISK_FIXTURE_CACHE/.incoming/$hash" "$dir"; rmdir "$BB_DISK_FIXTURE_CACHE/.incoming"
  guest_stop; trap - EXIT
  rm -rf "${G:?}" "$W/cache/cloudimg"
  log "RESULT fixtures PASS built $hash in $((t1 - t0))s; $(du -sh "$dir" | cut -f1) on disk, $(du -sh --apparent-size "$dir" | cut -f1) apparent"
}

step_lock() {
  log "build/beastnet/lock.py (downloads and checks every package of packages.in)"
  nice -n 10 python3 -I build/beastnet/lock.py
  log "RESULT lock PASS packages.lock rewritten"
}

step_disks() {
  venv
  [ -f "$BB_DIST_DIR/manifest.json" ] || die "no dist (run the helper step first)"
  nice -n 10 "$VENV/bin/python" -m pytest -q -p no:cacheprovider -rsfE --tb=short \
    --junitxml="$LOGS/disks.xml" tests/e2e/test_e2e_disks.py tests/e2e/test_e2e_disks_copy.py "$@"
}

step_e2e() {
  venv
  [ -f "$BB_DIST_DIR/manifest.json" ] || die "no dist (run the helper step first)"
  [ "$#" -gt 0 ] || set -- tests/e2e --ignore=tests/e2e/test_e2e_disks.py --ignore=tests/e2e/test_e2e_disks_copy.py
  nice -n 10 "$VENV/bin/python" -m pytest -q -p no:cacheprovider -rsfE --tb=short \
    --junitxml="$LOGS/e2e.xml" "$@"
}

step_signflow() {
  local d="$W/signflow" n id_a id_b
  # expect_refusal WHAT LOG CMD...: CMD must fail; its output goes to LOG
  expect_refusal() {
    local what="$1" out="$2"; shift 2
    if "$@" > "$out" 2>&1; then log "RESULT signflow FAIL $what was accepted (see $out)"; return 1; fi
    log "refused as it must be: $what: $(grep -m1 'error:' "$out" | cut -c1-160)"
  }
  rm -rf "${d:?}"; mkdir -p "$d"
  # key-build: what the `unsigned` job has (its own throw-away CA and leaves).
  # ca: the release CA, offline. key-sign: what the `sign` job has (the three leaves and
  # the CA certificate, no CA key).
  BB_KEY_DIR="$d/key-build" BB_KEY_CN="beast-boot signflow build CA" build/keygen.sh >/dev/null
  BB_CA_DIR="$d/ca" BB_KEY_DIR="$d/key-sign" BB_KEY_CN="beast-boot signflow release CA" build/keygen.sh ca >/dev/null
  BB_CA_DIR="$d/ca" BB_KEY_DIR="$d/key-sign" build/keygen.sh leaf all >/dev/null
  [ ! -e "$d/key-sign/beast-boot-ca.key" ] || { log "RESULT signflow FAIL the CA key is among the leaves"; return 1; }
  log "1/7 build with the first keys, keeping the unsigned images"
  BB_KEY_DIR="$d/key-build" BB_DIST_DIR="$d/dist-unsigned" BB_UNSIGNED_OUT="$d/unsigned" nice -n 10 build/build.sh
  log "2/7 build/sign.sh with the leaves of the second CA"
  BB_KEY_DIR="$d/key-sign" build/sign.sh "$d/unsigned" "$d/signed"
  for n in 1 2; do
    log "$((n + 2))/7 build without a private key from the signed images (BB_PRESIGNED_DIR), run $n"
    BB_KEY_DIR="$d/signed" BB_PRESIGNED_DIR="$d/signed" BB_DIST_DIR="$d/dist-$n" nice -n 10 build/build.sh
  done
  if find "$d/signed" -name '*.key' | grep -q .; then log "RESULT signflow FAIL build/sign.sh wrote a key"; return 1; fi
  diff -r "$d/dist-1" "$d/dist-2" || { log "RESULT signflow FAIL the two key-less builds differ"; return 1; }
  build/verify-dist.sh "$d/dist-1" --cert "$d/ca/beast-boot.crt" || { log "RESULT signflow FAIL verify-dist.sh"; return 1; }
  id_a="$(python3 -I build/bbtool.py manifest-get "$d/dist-unsigned" build_id)"
  id_b="$(python3 -I build/bbtool.py manifest-get "$d/dist-1" build_id)"
  [ "$id_a" = "$id_b" ] || { log "RESULT signflow FAIL build id $id_a with the first keys, $id_b signed with the second"; return 1; }

  log "5/7 negatives: a file signed with another component's leaf, leaves of another CA, renamed leaf files"
  # wimboot signed with the GRUB leaf, otherwise the good set
  cp -r "$d/signed" "$d/bad-swapped"
  sbsign --key "$d/key-sign/beast-boot-grub.key" --cert "$d/key-sign/beast-boot-grub.crt" \
    --output "$d/bad-swapped/wimboot" "$d/unsigned/wimboot" >/dev/null 2>&1
  expect_refusal "wimboot signed with the GRUB leaf (BB_PRESIGNED_DIR)" "$d/bad-swapped.log" \
    env BB_KEY_DIR="$d/bad-swapped" BB_PRESIGNED_DIR="$d/bad-swapped" BB_DIST_DIR="$d/dist-bad" nice -n 10 build/build.sh || return 1
  # ... and with the certificate files renamed to match (the GRUB leaf posing as the wimboot leaf)
  cp "$d/key-sign/beast-boot-grub.crt" "$d/bad-swapped/beast-boot-wimboot.crt"
  expect_refusal "the GRUB leaf renamed to the wimboot leaf (BB_PRESIGNED_DIR)" "$d/bad-renamed.log" \
    env BB_KEY_DIR="$d/bad-swapped" BB_PRESIGNED_DIR="$d/bad-swapped" BB_DIST_DIR="$d/dist-bad" nice -n 10 build/build.sh || return 1
  # the first key set's leaves under the second CA's certificate
  cp -r "$d/key-build" "$d/bad-ca"; rm -f "$d/bad-ca/beast-boot-ca.key"
  cp "$d/ca/beast-boot.crt" "$d/ca/beast-boot.cer" "$d/bad-ca/"
  expect_refusal "leaves of another CA (build/sign.sh)" "$d/bad-ca.log" \
    env BB_KEY_DIR="$d/bad-ca" build/sign.sh "$d/unsigned" "$d/bad-ca-out" || return 1
  # build/sign.sh with swapped leaf files
  cp -r "$d/key-sign" "$d/bad-keys"
  cp "$d/key-sign/beast-boot-grub.key" "$d/bad-keys/beast-boot-wimboot.key"
  cp "$d/key-sign/beast-boot-grub.crt" "$d/bad-keys/beast-boot-wimboot.crt"
  expect_refusal "the GRUB leaf in the wimboot leaf's place (build/sign.sh)" "$d/bad-keys.log" \
    env BB_KEY_DIR="$d/bad-keys" build/sign.sh "$d/unsigned" "$d/bad-keys-out" || return 1

  log "6/7 a replaced leaf: a new wimboot leaf from the same CA, signed again"
  cp "$d/key-sign/beast-boot-wimboot.crt" "$d/wimboot-old.crt"
  BB_CA_DIR="$d/ca" BB_KEY_DIR="$d/key-sign" build/keygen.sh leaf wimboot --force >/dev/null
  BB_KEY_DIR="$d/key-sign" build/sign.sh "$d/unsigned" "$d/signed-2" >/dev/null
  log "7/7 key-less build with the replaced wimboot leaf"
  BB_KEY_DIR="$d/signed-2" BB_PRESIGNED_DIR="$d/signed-2" BB_DIST_DIR="$d/dist-3" nice -n 10 build/build.sh
  [ "$(python3 -I build/bbtool.py manifest-get "$d/dist-3" build_id)" = "$id_b" ] \
    || { log "RESULT signflow FAIL the build id changed with a replaced leaf"; return 1; }
  cmp -s "$d/dist-1/esp/ENROLL_THIS_KEY_IN_MOKMANAGER.cer" "$d/dist-3/esp/ENROLL_THIS_KEY_IN_MOKMANAGER.cer" \
    || { log "RESULT signflow FAIL the certificate to enroll changed with a replaced leaf"; return 1; }
  if python3 -I scripts/efi_inspect.py require "$d/dist-3/esp/beast-booter/wimboot" --only "old leaf=$d/wimboot-old.crt" >/dev/null 2>&1; then
    log "RESULT signflow FAIL the new wimboot still verifies with the replaced leaf"; return 1
  fi
  build/verify-dist.sh "$d/dist-3" --cert "$d/ca/beast-boot.crt" >/dev/null || { log "RESULT signflow FAIL verify-dist.sh after the leaf was replaced"; return 1; }
  log "RESULT signflow PASS build $id_b: unsigned out; signed with three leaves of a second CA (no CA key where files are signed); two key-less rebuilds byte-identical; verify-dist ok; 4 wrong-leaf cases refused; a replaced leaf needs no new CA and keeps the build id"
  rm -rf "${d:?}"
}

step_sbomcheck() {
  # scripts/install-tools.sh downloads the pinned, hash-checked syft, grype, osv-scanner and JSON schemas
  # into .tools (/w/tools); the scan itself (vulnerability databases) is not run here
  [ -f "$BB_DIST_DIR/manifest.json" ] || die "no dist (run the helper step first)"
  [ -e "$REPO/dist" ] || ln -s "$BB_DIST_DIR" "$REPO/dist"
  local fails=""
  bash scripts/install-tools.sh || fails="$fails install-tools.sh"
  bash scripts/sbom-vuln.sh sbom || fails="$fails sbom-vuln.sh-sbom"
  python3 -I scripts/selftest.py || fails="$fails selftest.py"
  if [ -n "$fails" ]; then log "RESULT sbomcheck FAIL:$fails"; return 1; fi
  log "RESULT sbomcheck PASS sbom-vuln.sh sbom (gen_sbom.py + validate_sbom.py) and scripts/selftest.py"
}

step_vulnscan() {
  [ -f "$BB_DIST_DIR/manifest.json" ] || die "no dist (run the helper step first)"
  [ -e "$REPO/dist" ] || ln -s "$BB_DIST_DIR" "$REPO/dist"
  local out="$W/out/vulns" rc=0 f
  bash scripts/install-tools.sh || { log "RESULT vulnscan FAIL install-tools.sh"; return 1; }
  bash scripts/sbom-vuln.sh sbom || { log "RESULT vulnscan FAIL sbom-vuln.sh sbom"; return 1; }
  nice -n 10 bash scripts/sbom-vuln.sh scan "$@" | tee "$LOGS/vulnscan.summary" || rc=$?
  rm -rf "${out:?}"; mkdir -p "$out"
  for f in vulnerabilities.json VULNERABILITIES.md vex.proposed.openvex.json validation.json; do
    [ ! -f "sbom/$f" ] || cp "sbom/$f" "$out/"
  done
  # exit 3: --fail-on reached or a boot-chain check had no data; exit 4: a scanner failed (partial counts)
  if [ "$rc" != 0 ]; then log "RESULT vulnscan FAIL scan exit $rc (reports in $out)"; return 1; fi
  log "RESULT vulnscan PASS $(grep -c '' "$LOGS/vulnscan.summary") summary lines; reports in $out"
}

step_kernelvex() {
  [ -f "$BB_DIST_DIR/manifest.json" ] || die "no dist (run the helper step first)"
  [ -e "$REPO/dist" ] || ln -s "$BB_DIST_DIR" "$REPO/dist"
  local out="$W/out/vulns" f
  bash scripts/install-tools.sh || { log "RESULT kernelvex FAIL install-tools.sh"; return 1; }
  bash scripts/sbom-vuln.sh sbom || { log "RESULT kernelvex FAIL sbom-vuln.sh sbom"; return 1; }
  nice -n 10 bash scripts/sbom-vuln.sh scan > "$LOGS/kernelvex.scan1" || { cat "$LOGS/kernelvex.scan1"; log "RESULT kernelvex FAIL first scan"; return 1; }
  nice -n 10 python3 -I scripts/kernel_vex.py "$@" || { log "RESULT kernelvex FAIL scripts/kernel_vex.py"; return 1; }
  nice -n 10 bash scripts/sbom-vuln.sh scan | tee "$LOGS/kernelvex.scan2" || { log "RESULT kernelvex FAIL second scan"; return 1; }
  rm -rf "${out:?}"; mkdir -p "$out"
  for f in vex.kernel.openvex.json kernel-vex-report.json vulnerabilities.json VULNERABILITIES.md vex.proposed.openvex.json validation.json; do
    [ ! -f "sbom/$f" ] || cp "sbom/$f" "$out/"
  done
  log "before: $(grep -h '^scan: open shipped' "$LOGS/kernelvex.scan1"); $(grep -h '^scan: closed' "$LOGS/kernelvex.scan1")"
  log "RESULT kernelvex PASS $(grep -c '"vulnerability"' sbom/vex.kernel.openvex.json) statements in vex.kernel.openvex.json; $(grep -h '^scan: open shipped' "$LOGS/kernelvex.scan2")"
}

step_sbom() {
  [ -f "$BB_DIST_DIR/manifest.json" ] || die "no dist (run the helper step first)"
  nice -n 10 build/verify-dist.sh "$BB_DIST_DIR" "$@" || { log "RESULT sbom FAIL build/verify-dist.sh $*"; return 1; }
  python3 -I scripts/gen_sbom.py --root "$REPO" --dist "$BB_DIST_DIR" --out "$W/out/sbom" 2> "$LOGS/sbom.err" \
    || { cat "$LOGS/sbom.err"; log "RESULT sbom FAIL scripts/gen_sbom.py"; return 1; }
  cat "$LOGS/sbom.err"
  if grep -q 'PROVENANCE ERROR' "$LOGS/sbom.err"; then log "RESULT sbom FAIL provenance errors"; return 1; fi
  log "RESULT sbom PASS verify-dist.sh${*:+ $*} ok, gen_sbom.py without provenance errors ($(du -sh "$W/out/sbom" | cut -f1))"
}

main() {
  local step="${1:?usage: inside.sh unit|helper|fixtures|disks|e2e|signflow|sbom|sbomcheck|vulnscan|kernelvex|lock [PYTEST_ARGS...]}"; shift
  if [ "$(id -u)" = 0 ]; then
    # only the lock step starts as root, for the system's `apt-get update`; everything else
    # (and every file written to /w) runs as the host user
    [ "$step" = lock ] || die "only the lock step may start as root"
    apt-get update -qq
    exec setpriv --reuid="${HOST_UID:?}" --regid="${HOST_GID:?}" --clear-groups \
      bash "$REPO/devtools/e2e-kvm-host/inside.sh" lock
  fi
  setup
  case "$step" in
    unit|helper|fixtures|disks|e2e|signflow|sbom|sbomcheck|vulnscan|kernelvex|lock) "step_$step" "$@" ;;
    *) die "unknown step $step" ;;
  esac
}

main "$@"
