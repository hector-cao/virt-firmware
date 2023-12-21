#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" authenticode support """
import sys
import hashlib
import logging
import argparse
import subprocess

import pefile

from virt.firmware.varstore import linux

from virt.peutils import pesign

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

def pe_check_variable(digest, siglist, name, variable):
    found = False
    cert = pesign.pe_check_cert(siglist, variable)
    if cert:
        print(f'#   cert in \'{name}\' ({pesign.cert_common_name(cert.subject)})')
        found = True
    if pesign.pe_check_hash(digest, variable):
        print(f'#   hash in \'{name}\'')
        found = True
    return found

def pe_check(digest, siglist, varlist):
    if pe_check_variable(digest, siglist, 'dbx', varlist.get('dbx')):
        print('#   FAIL (dbx)')
        return

    if pe_check_variable(digest, siglist, 'MokListXRT', varlist.get('MokListXRT')):
        print('#   FAIL (MokListXRT)')
        return

    if pe_check_variable(digest, siglist, 'db', varlist.get('db')):
        print('#   PASS (db)')
        return

    if pe_check_variable(digest, siglist, 'MokListRT', varlist.get('MokListRT')):
        print('#   PASS (MokListRT -> needs shim.efi)')
        return

    print('#   FAIL (not found)')
    return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('--findcert', dest = 'findcert',
                        action = 'store_true', default = False,
                        help = 'print more certificate details')
    parser.add_argument("FILES", nargs='*',
                        help="List of PE files to dump")
    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    varlist = None
    if options.findcert:
        varlist = linux.LinuxVarStore().get_varlist(volatile = True)

    for filename in options.FILES:
        print(f'# file: {filename}')

        with pefile.PE(filename) as pe:
            digest = pe_authenticode_hash(pe)
            siglist = pesign.pe_type2_signatures(pe)

        print(f'#   digest: {digest.hex()}')

        # double-check hash (temporary)
        rc = subprocess.run(['pesign', '-h', '-i', filename ],
                            stdout = subprocess.PIPE,
                            check = True)
        line = rc.stdout.decode().split()[0]
        print(f'#   pesign: {line}')

        if varlist:
            pe_check(digest, siglist, varlist)

    return 0

if __name__ == '__main__':
    sys.exit(main())
