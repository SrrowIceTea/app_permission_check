#!/system/bin/sh
# Real Linux development backend in an owned AAOS emulator. 授权测试专用。
# Entry: unshare -m sh backend_namespace.sh ROOT SCRIPT [args...]
# This Android kernel rejects PID/IPC/UTS namespaces (EINVAL); do not claim them.
set -eu
ROOT=$1
shift
case "$ROOT" in /data/local/tmp/vscanner-ha/root) ;; *) exit 64 ;; esac
# Toybox requires an explicit source operand for propagation-only mount calls.
mount -o rprivate none /
mkdir -p "$ROOT/proc" "$ROOT/dev" "$ROOT/tmp"
mount -t proc proc "$ROOT/proc"
# A private tmpfs avoids /data's nodev flag without exposing Android /dev.
for devroot in "$ROOT/dev" "$ROOT/abs-root/dev"; do
    [ -d "$devroot" ] || continue
    mount -t tmpfs -o mode=755,nosuid tmpfs "$devroot"
    for spec in null:3 zero:5 random:8 urandom:9; do
        node=${spec%:*}
        minor=${spec#*:}
        mknod "$devroot/$node" c 1 "$minor"
        chmod 666 "$devroot/$node"
    done
done
chmod 1777 "$ROOT/tmp"
export PYTHONPATH=/packages
export PATH=/python/bin:/usr/local/bin:/usr/bin:/bin
# Do not mount Binder, Android data, host network directories or hardware devices.
# Network is shared intentionally for APK -> loopback; HA binds only 127.0.0.1.
exec /system/bin/chroot "$ROOT" /python/bin/python3.14 "$@"
