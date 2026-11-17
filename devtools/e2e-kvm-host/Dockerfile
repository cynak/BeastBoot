# Purpose: test environment for devtools/e2e-on-kvm-host.sh: BeastBoot's build image
#          (build/Containerfile, passed as BASE) plus QEMU/OVMF, the e2e fixture tools, sfdisk and
#          sgdisk (the installer's image tests check its drives with them) and
#          python3-venv for requirements-dev.txt. Built and run on the test server only, never with
#          --privileged; the container gets /dev/kvm and nothing else from the host.
ARG BASE
FROM ${BASE}
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      qemu-system-x86 qemu-utils ovmf seabios ipxe-qemu \
      mtools dosfstools exfatprogs ntfs-3g xorriso squashfs-tools socat cpio e2fsprogs fdisk gdisk \
      python3-venv python3-virt-firmware python3-pefile python3-jsonschema python3-referencing \
      openssh-client curl \
 && rm -rf /var/lib/apt/lists/*
