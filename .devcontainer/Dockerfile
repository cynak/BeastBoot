# beast-booter development container (VS Code Dev Containers / devcontainer CLI).
#
# NOTE: written without access to a container runtime; not yet tested.
# See docs/DEVELOPMENT.md ("Dev container") for how to use it.
#
# This is a *development* environment: the packages below are the ones the
# header of scripts/bootstrap-tools.sh lists for a system-wide install, plus a
# debugger and a few helpers. Release builds use build/Containerfile, which
# pins every package version. apt verifies every package against the signed
# Ubuntu archive index. For a fully pinned base, build with
#   --build-arg BASE_IMAGE=docker.io/library/ubuntu:26.04@sha256:<digest>
ARG BASE_IMAGE=docker.io/library/ubuntu:26.04
FROM ${BASE_IMAGE}

ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 TZ=UTC

# 1. The apt line from the header of scripts/bootstrap-tools.sh (it already
#    has gdb, socat and the GRUB debug symbols; grub-*-dbg pin themselves to
#    the exact grub-*-bin version, which is what `bb-dev gdb` needs).
# 2. python3-venv (.venv for bb-dev setup).
# 3. What the build, installer and helper scripts call: make, git, sfdisk
#    (fdisk), blkid (util-linux), openssl, objcopy (binutils), grub-mkimage
#    (grub-common), curl/gnupg/unzip/xz for the pinned ShellCheck and SBOM
#    tool downloads, procps (ps), file, less.
# The apt lists are kept on purpose: scripts/bootstrap-tools.sh and bb-dev
# fetch packages rootless with `apt-get download`, which needs them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      grub-pc-bin grub-efi-amd64-bin grub-efi-amd64-signed shim-signed \
      sbsigntool mtools dosfstools exfatprogs ntfs-3g xorriso socat \
      qemu-system-x86 qemu-system-gui ovmf python3-pytest python3-virt-firmware \
      grub-pc-dbg grub-efi-amd64-dbg gdb \
      python3-venv \
      ca-certificates make git fdisk util-linux openssl binutils grub-common \
      python3 curl gnupg unzip xz-utils procps file less \
      fonts-noto-core fonts-noto-mono gdisk

# Non-root user. Ubuntu images ship a user "ubuntu" with UID 1000; replace it
# so USER_UID/USER_GID are free. VS Code's updateRemoteUserUID then maps the
# UID/GID to yours. KVM access comes from runArgs (--group-add) at run time.
RUN set -eux; \
    if id -u ubuntu >/dev/null 2>&1; then userdel --remove ubuntu || userdel ubuntu || true; fi; \
    if getent group ubuntu >/dev/null 2>&1; then groupdel ubuntu || true; fi; \
    if ! getent group "${USER_GID}" >/dev/null 2>&1; then groupadd --gid "${USER_GID}" "${USERNAME}"; fi; \
    useradd --uid "${USER_UID}" --gid "${USER_GID}" --create-home --shell /bin/bash "${USERNAME}"; \
    if getent group kvm >/dev/null 2>&1; then usermod -aG kvm "${USERNAME}"; fi

USER ${USERNAME}
CMD ["sleep", "infinity"]
