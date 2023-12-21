#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" certificate and signature helper functions """
import struct

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

from virt.firmware.efi import guids

def cert_common_name(cert):
    try:
        scn = cert.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        return scn.value
    except IndexError:
        return 'no CN'

def pe_type2_signatures(pe):
    siglist = []
    sighdr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if sighdr.VirtualAddress and sighdr.Size:
        sigs = pe.__data__[ sighdr.VirtualAddress :
                            sighdr.VirtualAddress + sighdr.Size ]
        pos = 0
        while pos + 8 < len(sigs):
            (slen, srev, stype) = struct.unpack_from('<LHH', sigs, pos)
            if stype == 2:
                siglist.append(sigs [ pos + 8 : pos + slen ])
            pos += slen
            pos = (pos + 7) & ~7 # align
    return siglist

def pe_check_cert(siglist, variable):
    if not variable:
        return None
    for sig in siglist:
        sigcerts = pkcs7.load_der_pkcs7_certificates(sig)
        for sigcert in sigcerts:
            for dbcert in variable.sigdb:
                if dbcert.x509:
                    try:
                        sigcert.verify_directly_issued_by(dbcert.x509)
                        return sigcert
                    except (ValueError, TypeError):
                        pass
                    if sigcert == dbcert.x509:
                        return sigcert
    return None

def pe_check_hash(digest, variable):
    if not variable:
        return False
    return variable.sigdb.has_sig(guids.EfiCertSha256, digest)
