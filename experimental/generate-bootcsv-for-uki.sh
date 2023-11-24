#!/bin/sh
#
# Generate $ESP/EFI/$distro/BOOT$ARCH.CSV
#
# Usually 'kernel-bootcfg --update-csv' is better suited for the job,
# it will read the UEFI boot configuration from UEFI variables and
# create an BOOT.CSV which will restore that UEFI boot configuration
# if needed.
#
# When installing to a chroot this might not be what you want though.
# In that case this script can be used to generate a BOOT.CVS by not
# using UEFI variables at all, instead check what UKI kernels are
# available in in $ESP/EFI/Linux.
#

# args
esp="$1"

# check
if test ! -d "$1/EFI"; then
    echo "usage: $0 <esp>"
    exit 1
fi

# figure efi arch name
case "$(uname -m)" in
    aarch64)
        arch="aa64"
        ARCH="AA64"
        ;;
    x86_64)
        arch="x64"
        ARCH="X64"
        ;;
esac

msg_stderr() {
    echo "$1" 1>&2
}

# go!
shim="$(ls $esp/EFI/*/shim${arch}.efi)"
csv="${shim%/*}/BOOT${ARCH}.CSV.test"
if test -f /etc/machine-id; then
    mid="$(cat /etc/machine-id)"
else
    mid=""
fi
msg_stderr "# generate $csv"

echo -ne '\xff\xfe' > "$csv"
ukis="$(ls --sort=time --reverse $esp/EFI/Linux/*.efi)"
for uki in $ukis; do
    name="$(basename $uki .efi)"
    name="${name#${mid}-}"
    msg_stderr "#    add $name"
    echo "shimx64.efi,$name,${uki#$esp} ,comment"
done \
    | tr '/' '\\' \
    | iconv -f utf-8 -t ucs-2le >> "$csv"
