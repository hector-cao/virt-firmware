#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" print and edit ovmf varstore files """
import sys
import json
import logging
import argparse

from virt.firmware.efi import efivar
from virt.firmware.efi import efijson
from virt.firmware.efi import devpath
from virt.firmware.efi import ucs16
from virt.firmware.efi import certs

from virt.firmware.varstore import aws
from virt.firmware.varstore import jstore
from virt.firmware.varstore import autodetect


##################################################################################################
# main

# pylint: disable=too-many-branches,too-many-statements
def main():
    parser = argparse.ArgumentParser(
        description = "Print and modify EFI variable stores.")

    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('-i', '--input', dest = 'input', type = str,
                        help = 'read edk2 or aws vars from FILE', metavar = 'FILE')
    parser.add_argument('--inplace', '--in-place', dest = 'inplace', type = str,
                        help = 'modify FILE in place', metavar = 'FILE')
    parser.add_argument('--extract-certs', dest = 'extract',
                        action = 'store_true', default = False,
                        help = 'extract all certificates')

    pgroup = parser.add_argument_group('Variable options')
    pgroup.add_argument('-d', '--delete', dest = 'delete',
                        action = 'append', type = str,
                        help = 'delete variable VAR, can be specified multiple times',
                        metavar = 'VAR')
    pgroup.add_argument('--set-true', dest = 'set_true',
                        action = 'append', type = str,
                        help = 'set variable VAR to true, can be specified multiple times',
                        metavar = 'VAR')
    pgroup.add_argument('--set-false', dest = 'set_false',
                        action = 'append', type = str,
                        help = 'set variable VAR to false, can be specified multiple times',
                        metavar = 'VAR')
    pgroup.add_argument('--set-json', dest = 'set_json', type = str,
                        help = 'set variables from json dump FILE',
                        metavar = 'FILE')

    pgroup = parser.add_argument_group('Boot configuration')
    pgroup.add_argument('--set-boot-uri', dest = 'set_boot_uri',
                        help = 'set network boot uri to LINK (once, using BootNext)',
                        metavar = 'LINK')
    pgroup.add_argument('--append-boot-filepath', dest = 'append_boot_filepath',
                        action = 'append', type = str,
                        help = 'append boot entry for FILE (permanent, using BootOrder)',
                        metavar = 'FILE')

    pgroup = parser.add_argument_group('shim.efi configuration')
    pgroup.add_argument('--set-shim-debug', dest = 'set_shim_debug',
                        action = 'store_true', default = False,
                        help = 'enable shim.efi debugging (pause for debugger attach)')
    pgroup.add_argument('--set-shim-verbose', dest = 'set_shim_verbose',
                        action = 'store_true', default = False,
                        help = 'enable shim.efi verbose messages')
    pgroup.add_argument('--set-fallback-verbose', dest = 'set_fallback_verbose',
                        action = 'store_true', default = False,
                        help = 'enable fallback.efi verbose messages')
    pgroup.add_argument('--set-fallback-no-reboot', dest = 'set_fallback_no_reboot',
                        action = 'store_true', default = False,
                        help = 'disable rebooting for fallback.efi')
    pgroup.add_argument('--set-sbat-level', dest = 'sbatlevel', type = str,
                        help = 'set SbatLevel variable', metavar = 'FILE')

    pgroup = parser.add_argument_group('Secure boot setup options')
    pgroup.add_argument('--set-pk', dest = 'pk',  nargs = 2,
                        help = 'set PK to x509 cert, loaded in pem format ' +
                        'from FILE and with owner GUID',
                        metavar = ('GUID', 'FILE'))
    pgroup.add_argument('--add-kek', dest = 'kek',  action = 'append', nargs = 2,
                        help = 'add x509 cert to KEK, loaded in pem format ' +
                        'from FILE and with owner GUID, can be specified multiple times',
                        metavar = ('GUID', 'FILE'))
    pgroup.add_argument('--add-db', dest = 'db',  action = 'append', nargs = 2,
                        help = 'add x509 cert to db, loaded in pem format ' +
                        'from FILE and with owner GUID, can be specified multiple times',
                        metavar = ('GUID', 'FILE'))
    pgroup.add_argument('--set-dbx', dest = 'dbx',
                        help = 'initialize dbx with update from FILE', metavar = 'FILE')
    pgroup.add_argument('--add-mok', dest = 'mok',  action = 'append', nargs = 2,
                        help = 'add x509 cert to MokList, loaded in pem format ' +
                        'from FILE and with owner GUID, can be specified multiple times',
                        metavar = ('GUID', 'FILE'))
    pgroup.add_argument('--add-db-hash', dest = 'db_hash',  action = 'append', nargs = 2,
                        help = 'add sha256 HASH to db, with owner GUID, ' +
                        'can be specified multiple times',
                        metavar = ('GUID', 'HASH'))
    pgroup.add_argument('--add-mok-hash', dest = 'mok_hash',  action = 'append', nargs = 2,
                        help = 'add sha256 HASH to MokList, with owner GUID, ' +
                        'can be specified multiple times',
                        metavar = ('GUID', 'HASH'))

    pgroup = parser.add_argument_group('Secure boot convinience shortcuts')
    pgroup.add_argument('--enroll-redhat', dest = 'redhat',
                        action = 'store_true', default = False,
                        help = 'enroll default certificates for redhat platform')
    pgroup.add_argument('--enroll-cert', dest = 'enroll_cert',
                        help = 'enroll using specified certificate', metavar = "CERT")
    pgroup.add_argument('--enroll-generate', dest = 'enroll_generate',
                        help = 'enroll using generated cert with given common name', metavar = "CN")
    pgroup.add_argument('--no-microsoft', dest = 'microsoft',
                        action = 'store_false', default = True,
                        help = 'do not add microsoft keys to db')
    pgroup.add_argument('--microsoft-kek', dest = 'ms_kek',
                        choices = [ 'none', '2011', '2023', 'all' ], default = 'all',
                        help = 'choose microsoft KEK keys to enroll')
    pgroup.add_argument('--distro-keys', dest = 'distro', type = str, action = 'append',
                        help = 'add ca keys for DISTRO', metavar = 'DISTRO')
    pgroup.add_argument('--distro-list', dest = 'distrolist',
                        action = 'store_true', default = False,
                        help = 'list known distros')
    pgroup.add_argument('--sb', '--secure-boot', dest = 'secureboot',
                        action = 'store_true', default = False,
                        help = 'enable secure boot mode')

    pgroup = parser.add_argument_group('Print options')
    pgroup.add_argument('-p', '--print', dest = 'print',
                        action = 'store_true', default = False,
                        help = 'print varstore')
    pgroup.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print varstore verbosely')
    pgroup.add_argument('-x', '--hexdump', dest = 'hexdump',
                        action = 'store_true', default = False,
                        help = 'print variable hexdumps')

    pgroup = parser.add_argument_group('Output options')
    pgroup.add_argument('-o', '--output', dest = 'output', type = str,
                        help = 'write edk2 or aws vars to FILE, using the same format '
                        'the --input FILE has.', metavar = 'FILE')
    pgroup.add_argument('--output-aws', dest = 'output_aws', type = str,
                        help = 'write aws vars to FILE', metavar = 'FILE')
    pgroup.add_argument('--output-json', dest = 'output_json', type = str,
                        help = 'write json dump to FILE', metavar = 'FILE')
    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    varstore = None
    varlist = efivar.EfiVarList()

    if options.distrolist:
        certs.list_distros()
        sys.exit(0)

    if options.inplace:
        if options.input:
            logging.error("using --inplace is incompatible with --input")
            sys.exit(1)
        if options.output:
            logging.error("using --inplace is incompatible with --output")
            sys.exit(1)
        options.input = options.inplace
        options.output = options.inplace

    if options.input:
        varstore = autodetect.open_varstore(options.input)
        if varstore is None:
            logging.error("unknown input file format")
            sys.exit(1)
        varlist = varstore.get_varlist()

    if options.extract:
        for (key, item) in varlist.items():
            sigdb = item.sigdb
            if sigdb:
                sigdb.extract_certs(key)

    if options.delete:
        for name in options.delete:
            varlist.delete(name)

    if options.set_true:
        for item in options.set_true:
            varlist.set_bool(item, True)

    if options.set_false:
        for item in options.set_false:
            varlist.set_bool(item, False)

    if options.set_boot_uri:
        items = options.set_boot_uri.split('/')
        title = 'netboot ' + items[-1]
        bpath = devpath.DevicePath.uri(options.set_boot_uri)
        varlist.set_boot_entry(0x99, title, bpath)
        varlist.set_boot_next(0x99)

    if options.append_boot_filepath:
        for item in options.append_boot_filepath:
            strings = item.replace('/', '\\').split(' ')
            filepath = strings[0]
            if len(strings) > 1:
                optdata = bytes(ucs16.from_string(strings[1]))
            else:
                optdata = None
            items = filepath.split('\\')
            title = 'file ' + items[-1]
            bpath = devpath.DevicePath.filepath(filepath)
            index = varlist.add_boot_entry(title, bpath, optdata)
            varlist.append_boot_order(index)

    if options.set_shim_debug:
        varlist.set_uint32('SHIM_DEBUG', 1)

    if options.set_shim_verbose:
        varlist.set_uint32('SHIM_VERBOSE', 1)

    if options.set_fallback_verbose:
        varlist.set_uint32('FALLBACK_VERBOSE', 1)

    if options.set_fallback_no_reboot:
        varlist.set_uint32('FB_NO_REBOOT', 1)

    if options.sbatlevel:
        varlist.set_from_file('SbatLevel', options.sbatlevel)

    if options.set_json:
        with open(options.set_json, "r", encoding = 'utf-8') as f:
            l = json.loads(f.read(), object_hook = efijson.efi_decode)
        for (key, item) in l.items():
            logging.info('set variable %s from %s', key, options.set_json)
            varlist[key] = item

    if options.redhat:
        varlist.enroll_platform_redhat(ms_kek = options.ms_kek)
        if options.microsoft:
            varlist.add_microsoft_keys()

    if options.enroll_cert:
        varlist.enroll_platform_with_cert(options.enroll_cert,
                                          ms_kek = options.ms_kek)
        if options.microsoft:
            varlist.add_microsoft_keys()

    if options.enroll_generate:
        varlist.enroll_platform_generate(options.enroll_generate,
                                         ms_kek = options.ms_kek)
        if options.microsoft:
            varlist.add_microsoft_keys()

    if options.distro:
        for item in options.distro:
            varlist.add_distro_keys(item)

    if options.pk:
        varlist.add_cert('PK', options.pk[0], options.pk[1], True)

    if options.kek:
        for item in options.kek:
            varlist.add_cert('KEK', item[0], item[1])

    if options.db:
        for item in options.db:
            varlist.add_cert('db', item[0], item[1])

    if options.dbx:
        logging.info('reading dbx update from %s', options.dbx)
        with open(options.dbx, 'rb') as f:
            dbxupdate = f.read()
        varlist['dbx'] = efivar.EfiVar(ucs16.from_string('dbx'),
                                       authdata = dbxupdate)

    if options.mok:
        for item in options.mok:
            varlist.add_cert('MokList', item[0], item[1])

    if options.db_hash:
        for item in options.db_hash:
            varlist.add_hash('db', item[0], item[1])

    if options.mok_hash:
        for item in options.mok_hash:
            varlist.add_hash('MokList', item[0], item[1])

    if options.secureboot:
        varlist.enable_secureboot()

    if options.print:
        if options.verbose:
            varlist.print_normal(options.hexdump)
        else:
            varlist.print_compact()

    if options.output:
        if varstore:
            varstore.write_varstore(options.output, varlist)
        else:
            logging.error("no input file specified (needed as edk2 varstore template)")
            sys.exit(1)

    if options.output_aws:
        if options.output_aws == "-":
            print(aws.AwsVarStore.base64_varstore(varlist).decode())
        else:
            aws.AwsVarStore.write_varstore(options.output_aws, varlist)

    if options.output_json:
        if options.output_json == "-":
            print(jstore.JsonVarStore.json_varstore(varlist))
        else:
            jstore.JsonVarStore.write_varstore(options.output_json, varlist)

    return 0

if __name__ == '__main__':
    sys.exit(main())
