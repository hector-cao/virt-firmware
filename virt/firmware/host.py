#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" print efi variables """
import sys
import logging
import argparse

from virt.firmware.varstore import linux


##################################################################################################
# main

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print varstore verbosely')
    parser.add_argument('-x', '--hexdump', dest = 'hexdump',
                        action = 'store_true', default = False,
                        help = 'print variable hexdumps')
    parser.add_argument('--volatile', dest = 'volatile',
                        action = 'store_true', default = False,
                        help = 'print volatile variables too')
    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    varstore = linux.LinuxVarStore()
    varlist = varstore.get_varlist(volatile = options.volatile)
    if options.verbose:
        varlist.print_normal(options.hexdump)
    else:
        varlist.print_compact()

    return 0

if __name__ == '__main__':
    sys.exit(main())
