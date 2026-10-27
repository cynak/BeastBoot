# beast-boot: exFAT support for a live ISO's own initramfs (initramfs-tools).
# shellcheck shell=sh
#
# The menu adds this file to the ISO's initramfs as
# /conf/conf.d/zz-beastbooter.conf, together with the ISO's own exfat module
# (taken from the ISO's squashfs, so it is signed for the ISO's kernel) under
# /beast-boot/modules/. The ISO's /init sources every conf.d file before it
# runs the boot scripts, so this runs early. It is sourced, not executed: never
# exit, and keep every failure quiet so the ISO boots exactly as it would have.
#
# What it does:
#   1. load each module under /beast-boot/modules/ (the kernel checks the
#      module signature itself; with Secure Boot an unsigned module is refused).
#      Ubuntu's PATH finds klibc's insmod first, which cannot load compressed
#      (.ko.zst, .ko.xz) modules, so kmod is used when the initramfs has it.
#   2. casper (Ubuntu) only mounts filesystem types from a fixed list. When a
#      module loaded, append a wider is_supported_fs to casper-helpers: every
#      casper script sources that file, so the last definition wins.
# Messages go to the kernel log: dmesg | grep beast-boot
#
# Test hook: BB_HOOK_ROOT prefixes every path (empty at boot).

bb_hook_root="${BB_HOOK_ROOT:-}"
bb_hook_log() {
    if [ -w "$bb_hook_root/dev/kmsg" ]; then
        echo "beast-boot: $*" >> "$bb_hook_root/dev/kmsg" 2>/dev/null || true
    fi
}
# bb_hook_insmod FILE: kmod's insmod (called through a link named insmod, as
# kmod picks the command from its own name), else whatever insmod PATH finds.
bb_hook_insmod() {
    for bb_hook_k in /usr/bin/kmod /bin/kmod /usr/sbin/kmod /sbin/kmod; do
        if [ -x "$bb_hook_root$bb_hook_k" ]; then
            mkdir -p "$bb_hook_root/beast-boot/bin" &&
                ln -sf "$bb_hook_root$bb_hook_k" "$bb_hook_root/beast-boot/bin/insmod" &&
                "$bb_hook_root/beast-boot/bin/insmod" "$1"
            return
        fi
    done
    insmod "$1"
}
bb_hook_fs=""     # "|exfat" for the case pattern below
bb_hook_names=""  # " exfat" for messages
for bb_hook_m in "$bb_hook_root"/beast-boot/modules/*.ko*; do
    [ -f "$bb_hook_m" ] || continue
    bb_hook_n="${bb_hook_m##*/}"
    bb_hook_n="${bb_hook_n%%.*}"
    bb_hook_out="$(bb_hook_insmod "$bb_hook_m" 2>&1)"
    if grep -q "[[:space:]]${bb_hook_n}\$" "$bb_hook_root/proc/filesystems" 2>/dev/null; then
        bb_hook_fs="${bb_hook_fs}|${bb_hook_n}"
        bb_hook_names="${bb_hook_names} ${bb_hook_n}"
        bb_hook_log "${bb_hook_n} support loaded (${bb_hook_m##*/} from the ISO)"
    else
        bb_hook_log "could not load ${bb_hook_m##*/}: ${bb_hook_out:-no error message}"
    fi
done
if [ -n "$bb_hook_fs" ] && [ -f "$bb_hook_root/scripts/casper-helpers" ]; then
    if cat >> "$bb_hook_root/scripts/casper-helpers" <<EOF

# Added by beast-boot (/conf/conf.d/zz-beastbooter.conf): also accept${bb_hook_names}.
is_supported_fs() {
    [ -z "\${1}" ] && return 1
    case \${1} in
        ext2|ext3|ext4|xfs|jfs|reiserfs|vfat|ntfs|iso9660|btrfs|udf${bb_hook_fs})
            return 0
            ;;
    esac
    return 1
}
EOF
    then
        bb_hook_log "casper may now search${bb_hook_names} partitions for the ISO"
    fi
fi
# live-boot (Debian) takes the NTFS type to need the ntfs-3g program, not a
# kernel module, so it skips an NTFS partition when `type ntfs-3g` fails, and
# then runs mount -t ntfs, a type the kernel only knows as ntfs3. With the ISO's
# ntfs3 module loaded give it both: a stand-in ntfs-3g for the check (never
# run) and a mount.ntfs helper, which mount(8) runs for -t ntfs, that mounts
# the partition as ntfs3.
case "$bb_hook_fs" in
    *"|ntfs3"*)
        if [ -d "$bb_hook_root/lib/live/boot" ] && ! command -v ntfs-3g >/dev/null 2>&1; then
            mkdir -p "$bb_hook_root/sbin" "$bb_hook_root/bin" 2>/dev/null
            printf '#!/bin/sh\nexit 1\n' > "$bb_hook_root/bin/ntfs-3g" 2>/dev/null &&
                printf '#!/bin/sh\nexec mount -i -t ntfs3 "$@"\n' > "$bb_hook_root/sbin/mount.ntfs" 2>/dev/null &&
                chmod 755 "$bb_hook_root/bin/ntfs-3g" "$bb_hook_root/sbin/mount.ntfs" 2>/dev/null &&
                bb_hook_log "live-boot may now search NTFS partitions for the ISO (ntfs3)"
        fi
        ;;
esac
unset bb_hook_root bb_hook_fs bb_hook_names bb_hook_m bb_hook_n bb_hook_out bb_hook_k
unset -f bb_hook_log bb_hook_insmod 2>/dev/null || true
