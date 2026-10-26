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

# d-i starts one installer per console (/sbin/reopen-console: the serial console
# of console=ttyS0 and tty1, say), but only the one on the preferred console when
# it sees a preseed: installers that no question stops run in parallel and trip
# over each other (two anna runs: "Installation step failed" at "Load installer
# components from installation media", or "No kernel modules were found"). It
# looks for /preseed.cfg and the words auto and url only. Answers on the kernel
# command line (bb_kargs: a question name, or an /etc/preseed_aliases alias such
# as priority, locale, keymap or file) preseed too, so do the same for them.
# This runs before reopen-console makes init start the installers.
bb_di_preseeded() {
    tr -s ' ' '\n' < /proc/cmdline 2>/dev/null | {
        while read -r bb_w; do
            case "$bb_w" in
                ?*=*) bb_k="${bb_w%%=*}" ;;
                *) continue ;;
            esac
            case "$bb_k" in
                */*) exit 0 ;;
                *[!A-Za-z0-9_-]*) continue ;;
            esac
            if grep -q "^${bb_k}[[:space:]]" /etc/preseed_aliases 2>/dev/null; then
                exit 0
            fi
        done
        exit 1
    }
}
bb_di_c="$(sed -n 's|^/dev/\([A-Za-z0-9]*\) *$|\1|p' /var/run/console-preferred 2>/dev/null)"
if [ -n "$bb_di_c" ] && [ "$(grep -c '::respawn:/sbin/debian-installer$' /etc/inittab 2>/dev/null)" -gt 1 ] 2>/dev/null && bb_di_preseeded; then
    if grep -v '::respawn:/sbin/debian-installer$' /etc/inittab > /tmp/bb-inittab 2>/dev/null &&
        echo "$bb_di_c::respawn:/sbin/debian-installer" >> /tmp/bb-inittab &&
        cat /tmp/bb-inittab > /etc/inittab; then
        echo "/dev/$bb_di_c " > /var/run/console-devices 2>/dev/null || true
        bb_di_log "preseeded command line: debian-installer on $bb_di_c only"
    fi
    rm -f /tmp/bb-inittab
fi
unset bb_di_c bb_m bb_n bb_w bb_k
unset -f bb_di_log bb_di_preseeded 2>/dev/null || true
