[description]

The virt-fw-vars utility can print and modify UEFI variable stores.
Supported formats are standard edk2 (as used by ovmf and armvirt) and
aws.

[examples]

.TP
Print variable store.
virt-fw-vars --input ${guest}_VARS.fd \\
             --print --verbose

.TP
Enroll default (microsoft) secure boot certificates
virt-fw-vars --input OVMF_VARS.fd \\
             --output OVMF_VARS.secboot.fd \\
             --enroll-redhat \\
             --secure-boot

[author]

Gerd Hoffmann <kraxel@redhat.com>

