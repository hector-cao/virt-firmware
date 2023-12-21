#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" certificate and signature helper functions """
import struct
import hashlib
import logging

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

from virt.firmware.efi import guids

def cert_common_name(cert):
    try:
        scn = cert.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        return scn.value
    except IndexError:
        return 'no CN'

def pe_authenticode_hash(pe, method = 'sha256'):
    h = hashlib.new(method)
    blob = pe.__data__

    csum_off = pe.OPTIONAL_HEADER.get_file_offset() + 0x40
    hdr_end = pe.OPTIONAL_HEADER.SizeOfHeaders

    # hash header, excluding checksum and security directory
    h.update(blob [ 0 : csum_off ])
    logging.debug('hash 0x%06x -> 0x%06x - header start -> csum', 0, csum_off)
    if pe.OPTIONAL_HEADER.NumberOfRvaAndSizes < 4:
        sec = None
        h.update(blob [ csum_off + 4 : hdr_end ])
        logging.debug('hash 0x%06x -> 0x%06x - header csum -> end', csum_off + 4, hdr_end)
    else:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        sec_off = sec.get_file_offset()
        h.update(blob [ csum_off + 4 : sec_off ])
        h.update(blob [ sec_off + 8 : hdr_end ])
        logging.debug('hash 0x%06x -> 0x%06x - header csum -> sigs', csum_off + 4, sec_off)
        logging.debug('hash 0x%06x -> 0x%06x - header sigs -> end', sec_off + 8, hdr_end)

    # hash sections
    offset = hdr_end
    for section in sorted(pe.sections, key = lambda s: s.PointerToRawData):
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        name = section.Name.rstrip(b'\0').decode()
        logging.debug('hash 0x%06x -> 0x%06x - section \'%s\'', start, end, name)
        if start != offset:
            logging.error('unexpected section start 0x%06x (expected 0x%06x, section \'%s\')',
                          start, offset, name)
        h.update(blob [ start : end ])
        offset = end

    # hash remaining data
    if sec and sec.Size:
        end = sec.VirtualAddress
    else:
        end = len(blob)
    if offset < end:
        h.update(blob [ offset : end ])
        logging.debug('hash 0x%06x -> 0x%06x - remaining data', offset, end)

    # hash dword padding
    padding = ((end + 3) & ~3) - end
    if padding:
        for i in range(padding):
            h.update(b'\0')
        logging.debug('hash %d padding byte(s)', padding)

    # log signatures and EOF
    if sec and sec.Size:
        start = sec.VirtualAddress
        end = start + sec.Size
        logging.debug('sigs 0x%06x -> 0x%06x', start, end)
    logging.debug('EOF  0x%06x', len(blob))

    return h.digest()

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

#
# This does only check whenever one of the certificates in the pkcs7
# signature is found in the given efi variable, either the certificate
# itself or the issuer of the certificate.
#
# The pkcs7 signature itself is NOT verified.
#
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
