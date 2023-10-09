#!/bin/sh

if test "$(id --user)" = "0"; then
    sudo=""
else
    sudo="sudo"
fi

function set_type() {
    local device="$1"
    local uuid="$2"
    local disk part

    disk="${device%[0-9]}"
    part="${device#$disk}"
    disk="${disk%p}"

    case "$disk" in
        /dev/sd* | /dev/vd* | /dev/nvme*)
            echo "# $disk $part -> $uuid"
            (set -x; $sudo sfdisk --part-type "$disk" "$part" "$uuid")
            ;;
        *)
            echo "# unknown device: $device"
            ;;
    esac
}

bootdev=$(mount | awk '$3 == "/boot" { print $1 }')
rootdev=$(mount | awk '$3 == "/"     { print $1 }')

# setup discoverable partitions
set_type $bootdev "BC13C2FF-59E6-4262-A352-B275FD6F7172"
case "$(uname -m)" in
    x86_64)	set_type $rootdev "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709";;
    aarch64)	set_type $rootdev "b921b045-1df0-41c3-af44-4c6f280d3fae";;
esac

# setup default subvolume for btrfs
rootfs=$(mount | awk '$3 == "/" { print $5 }')
if test "$rootfs" = "btrfs"; then
    rootid=$($sudo btrfs subvolume list / | awk '/path root/ { print $2 }')
    echo "# btrfs root subvolume id: $rootid"
    (set -x; $sudo btrfs subvolume set-default $rootid /)
fi
