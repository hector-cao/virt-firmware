#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" print and edit ovmf varstore files """
import sys
import logging
import argparse

from virt.firmware.varstore import edk2


##################################################################################################
# main

# pylint: disable=too-many-branches,too-many-statements
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('--template', dest = 'template', type = str,
                        help = 'use varstore template FILE', metavar = 'FILE',
                        default = '/usr/share/edk2/ovmf/OVMF_VARS.fd')
    parser.add_argument('--varstore', dest = 'varstores', type = str, action = 'append',
                        help = 'migrate variable store FILE', metavar = 'FILE', default = [])
    parser.add_argument('--guest', dest = 'guests', type = str, action = 'append',
                        help = 'migrate libvirt guest NAME', metavar = 'NAME', default = [])
    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    newstore = edk2.Edk2VarStore(options.template)

    for guest in options.guests:
        options.varstores.append(f'/var/lib/libvirt/qemu/nvram/{guest}_VARS.fd')

    for varsfile in options.varstores:
        oldstore = edk2.Edk2VarStore(varsfile)
        varlist = oldstore.get_varlist()
        newstore.write_varstore(varsfile, varlist)

    return 0

if __name__ == '__main__':
    sys.exit(main())
