#!/bin/sh
# beast-booter: debian-installer ISO as the installer's CD.
# GRUB adds the ISO to the initrd as /beast-booter/debian.iso and the ISO's own
# loop-modules udeb as /beast-booter/loop.udeb (the installer's kernel needs
# the loop module, which is not in its initrd). This runs as
# /usr/lib/debian-installer-startup.d/S45beast-iso (the initrd's /lib is a symlink
# to usr/lib that a newc entry must not replace), executed or sourced by
# debian-installer-startup: never "exit". It mounts the ISO on /cdrom, where
# cdrom-detect ("a cdrom is already mounted: assume it is the right one") and
# the CD package retriever find it.
bb_di_log() {
    if [ -w /dev/kmsg ]; then
        echo "beast-booter: $*" > /dev/kmsg 2>/dev/null || true
    fi
}
if [ -f /beast-booter/debian.iso ] && [ -f /beast-booter/loop.udeb ]; then
    mkdir -p /tmp/bb-loop /cdrom
    if ar p /beast-booter/loop.udeb data.tar.xz 2>/dev/null | xzcat 2>/dev/null | tar -x -C /tmp/bb-loop 2>/dev/null; then
        for bb_m in /tmp/bb-loop/lib/modules/*/kernel/drivers/block/loop.ko*; do
            case "$bb_m" in
                *.xz) xzcat "$bb_m" > /tmp/bb-loop/loop.ko 2>/dev/null ;;
                *) cp "$bb_m" /tmp/bb-loop/loop.ko ;;
            esac
        done
        insmod /tmp/bb-loop/loop.ko 2>/dev/null || modprobe loop 2>/dev/null || true
        bb_n=0
        while [ ! -b /dev/loop0 ] && [ "$bb_n" -lt 20 ]; do
            sleep 1
            bb_n=$((bb_n + 1))
        done
        if mount -t iso9660 -o ro,loop /beast-booter/debian.iso /cdrom 2>/dev/null; then
            bb_di_log "debian.iso mounted on /cdrom"
        else
            bb_di_log "mounting debian.iso failed"
        fi
    else
        bb_di_log "loop-modules udeb unreadable"
    fi
fi
