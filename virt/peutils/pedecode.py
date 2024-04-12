#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" functions to decode information from pe binaries """
import struct

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from virt.firmware.efi import guids
from virt.firmware.efi import siglist

def getcstr(data):
    """ get C string (terminated by null byte) """
    idx = 0
    for b in data:
        if b == 0:
            break
        idx += 1
    return data[:idx]

def pe_string(pe, index):
    """ lookup string in string table (right after symbol table) """
    strtab  = pe.FILE_HEADER.PointerToSymbolTable
    strtab += pe.FILE_HEADER.NumberOfSymbols * 18
    strtab += index
    return getcstr(pe.__data__[strtab:])

def pe_section_name(pe, sec):
    """ decode section name """
    if sec.Name.startswith(b'/'):
        idx = getcstr(sec.Name[1:])
        return pe_string(pe, int(idx))
    return getcstr(sec.Name)

def vendor_cert_sigdb(blob):
    # VENDOR_CERT_FILE -> create signature database
    try:
        crt = x509.load_der_x509_certificate(blob, default_backend())
        sl = siglist.EfiSigList(guid = guids.parse_str(guids.EfiCertX509))
        sl.add_sig(guids.parse_str(guids.Shim),
                        crt.public_bytes(serialization.Encoding.DER))
        sigdb = siglist.EfiSigDB()
        sigdb.append(sl)
        return sigdb
    except ValueError:
        pass

    # VENDOR_DB_FILE -> already is a signature datadase
    sigdb = siglist.EfiSigDB(blob)
    return sigdb

def pe_vendor_cert(section):
    db = None
    dbx = None
    vcert = section.get_data()
    (dbs, dbxs, dbo, dbxo) = struct.unpack_from('<IIII', vcert)
    if dbs:
        db = vcert [ dbo : dbo + dbs ]
    if dbxs:
        dbx = vcert [ dbxo : dbxo + dbxs ]
    return (db, dbx)
