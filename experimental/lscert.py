#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" list certificates """
import sys
import argparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend

attr_override = {
    x509.NameOID.EMAIL_ADDRESS : 'email'
}

def main():
    parser = argparse.ArgumentParser(
        description = 'list certificates')
    parser.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print more certificate details')
    parser.add_argument("FILES", nargs='*',
                        help="List of PE files to dump")
    options = parser.parse_args()

    flen = 0
    for filename in options.FILES:
        if flen < len(filename):
            flen = len(filename)

    for filename in options.FILES:
        # read filename
        with open(filename, 'rb') as f:
            blob = f.read()
        if b'-----BEGIN' in blob:
            cert = x509.load_pem_x509_certificate(blob, default_backend())
        else:
            cert = x509.load_der_x509_certificate(blob, default_backend())

        if options.verbose:
            # verbose
            name = cert.subject.rfc4514_string(attr_override)
            ds = str(cert.not_valid_before).split()[0]
            de = str(cert.not_valid_after).split()[0]
            print(f'{filename:{flen}s}: {ds} - {de}  {name}')

        else:
            # compact
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
            ys = cert.not_valid_before.year
            ye = cert.not_valid_after.year
            print(f'{filename:{flen}s}: {ys} - {ye}  {cn.value}')


if __name__ == '__main__':
    sys.exit(main())
