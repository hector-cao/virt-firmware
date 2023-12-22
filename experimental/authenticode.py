#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" authenticode support """
import sys
import logging
import argparse
import subprocess

import pefile

from virt.firmware.varstore import linux

from virt.peutils import pesign

def pe_check_variable(digest, siglist, name, variable):
    found = False
    cert = pesign.pe_check_cert(siglist, variable)
    if cert:
        found = True
        scn = pesign.cert_common_name(cert.subject)
        print(f'#   \'{scn}\' cert or issuer found in \'{name}\'')
    if pesign.pe_check_hash(digest, variable):
        found = True
        print(f'#   hash digest found in \'{name}\'')
    return found

def pe_check(digest, siglist, varlist):
    if pe_check_variable(digest, siglist, 'dbx', varlist.get('dbx')):
        print('#   -> FAIL (dbx)')
        return

    if pe_check_variable(digest, siglist, 'MokListXRT', varlist.get('MokListXRT')):
        print('#   -> FAIL (MokListXRT)')
        return

    if pe_check_variable(digest, siglist, 'db', varlist.get('db')):
        print('#   -> PASS (db)')
        return

    if pe_check_variable(digest, siglist, 'MokListRT', varlist.get('MokListRT')):
        print('#   -> PASS (MokListRT, needs shim.efi)')
        return

    print('#   -> FAIL (not found)')
    return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('--findcert', '--find-cert', dest = 'findcert',
                        action = 'store_true', default = False,
                        help = 'check EFI databases for certs')
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
            digest = pesign.pe_authenticode_hash(pe)
            siglist = pesign.pe_type2_signatures(pe)

        print(f'#   digest: {digest.hex()}')

        # double-check hash calculation (temporary)
        rc = subprocess.run(['pesign', '-h', '-i', filename ],
                            stdout = subprocess.PIPE,
                            check = True)
        line = rc.stdout.decode().split()[0]
        if line != digest.hex():
            logging.error('digest mismatch (pesign: %s)', line)

        if varlist:
            pe_check(digest, siglist, varlist)

    return 0

if __name__ == '__main__':
    sys.exit(main())
