#!/bin/sh
# beast-booter: Alpine Linux ISO file as the boot medium.
# Alpine's initramfs finds its boot medium (apks, modloop) by scanning block
# devices for /apks/.boot_repository, and has no way to open an ISO file. GRUB
# adds the ISO to the initramfs as /beast-booter/alpine.iso and starts this
# script instead of /init (kernel parameter rdinit=/beast-init). It attaches
# the ISO to a loop device, undoes its own mounts and hands over to Alpine's
# /init, whose device scan then finds the ISO on /dev/loop0 like a CD.
B=/bin/busybox
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
$B mkdir -p /proc /sys /dev
$B mount -t proc proc /proc 2>/dev/null
$B mount -t sysfs sysfs /sys 2>/dev/null
$B mount -t devtmpfs devtmpfs /dev 2>/dev/null
modprobe loop 2>/dev/null
bb_n=0
while [ ! -b /dev/loop0 ] && [ "$bb_n" -lt 50 ]; do
    $B sleep 0.1
    bb_n=$((bb_n + 1))
done
if $B losetup -r /dev/loop0 /beast-booter/alpine.iso 2>/dev/null; then
    echo "beast-booter: alpine.iso attached to /dev/loop0" > /dev/kmsg 2>/dev/null
else
    echo "beast-booter: attaching alpine.iso failed" > /dev/kmsg 2>/dev/null
fi
$B umount /dev 2>/dev/null
$B umount /sys 2>/dev/null
$B umount /proc 2>/dev/null
exec /init "$@"
