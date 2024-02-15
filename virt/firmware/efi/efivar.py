#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
# pylint: disable=too-many-public-methods
""" efi variables """

import re
import struct
import logging
import datetime
import collections

from cryptography import x509

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import certs
from virt.firmware.efi import devpath
from virt.firmware.efi import siglist
from virt.firmware.efi import bootentry

##################################################################################################
# constants

# variable attributes
EFI_VARIABLE_NON_VOLATILE                          = 0x00000001
EFI_VARIABLE_BOOTSERVICE_ACCESS                    = 0x00000002
EFI_VARIABLE_RUNTIME_ACCESS                        = 0x00000004
EFI_VARIABLE_HARDWARE_ERROR_RECORD                 = 0x00000008
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS            = 0x00000010  # deprecated
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020
EFI_VARIABLE_APPEND_WRITE                          = 0x00000040

EFI_VARIABLE_DEFAULT = (EFI_VARIABLE_NON_VOLATILE |
                        EFI_VARIABLE_BOOTSERVICE_ACCESS)

efivar_defaults = {
    'SecureBoot' : {
        'attr' : (EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS),
        'guid' : guids.EfiGlobalVariable,
    },
    'SecureBootEnable' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.EfiSecureBootEnableDisable,
    },
    'CustomMode' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.EfiCustomModeEnable,
    },
    'PK' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiGlobalVariable,
    },
    'KEK' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiGlobalVariable,
    },
    'db' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiImageSecurityDatabase,
    },
    'dbx' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS |
                  EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
        'guid' : guids.EfiImageSecurityDatabase,
    },
    'MokList' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.Shim,
    },
    'MokListX' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.Shim,
    },
    'MokListTrusted' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.Shim,
    },
    'SbatLevel' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.Shim,
    },
    'SHIM_DEBUG' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.Shim,
    },
    'SHIM_VERBOSE' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.Shim,
    },
    'FALLBACK_VERBOSE' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
        'guid' : guids.Shim,
    },
    'FB_NO_REBOOT' : {
        'attr' : (EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS),
        'guid' : guids.Shim,
    },
}

boot_defaults = {
    'attr' : (EFI_VARIABLE_NON_VOLATILE |
              EFI_VARIABLE_BOOTSERVICE_ACCESS |
              EFI_VARIABLE_RUNTIME_ACCESS),
    'guid' : guids.EfiGlobalVariable,
}

sigdb_names = ("PK", "KEK", "db", "dbx", "MokList", "MokListX", "TlsCaCertificate",
               "MokListRT", "MokListXRT")
bool_names  = ('SecureBootEnable', 'CustomMode')
ascii_names = ('Lang', 'PlatformLang', 'SbatLevel')
blist_names = ('BootOrder', 'BootNext')
dpath_names = ('ConIn', 'ConOut', 'ErrOut')

initial_ts  = datetime.datetime(2010, 1, 1)

##################################################################################################

# pylint: disable=too-many-arguments,too-many-instance-attributes
class EfiVar:
    """  class for efi variables """

    def __init__(self, name,
                 guid = None,
                 attr = None,
                 data = b'',
                 count = 0,
                 pkidx = 0,
                 authdata = None):
        self.name = name
        self.guid = guid
        self.attr = attr
        self.data = data
        self.count = count
        self.pkidx = pkidx
        self.time = None
        self.sigdb = None

        defaults = efivar_defaults.get(str(name))
        if defaults is None and str(name).startswith('Boot'):
            defaults = boot_defaults

        if self.guid is None:
            if defaults:
                self.guid = guids.parse_str(defaults['guid'])
            else:
                self.guid = guids.parse_str(guids.EfiGlobalVariable)
        if self.attr is None:
            if defaults:
                self.attr = defaults['attr']
            else:
                self.attr = EFI_VARIABLE_DEFAULT

        if authdata:
            self.parse_authdata(authdata)

        if str(self.name) in sigdb_names:
            self.sigdb = siglist.EfiSigDB(self.data)

    def parse_time(self, data, offset):
        """ parse struct EFI_TIME """
        (year, month, day, hour, minute, second, ns, tz, dl) = \
            struct.unpack_from("=HBBBBBxLhBx", data, offset)
        if year:
            self.time = datetime.datetime(year, month, day,
                                          hour, minute, second,
                                          int(ns / 1000))
        else:
            self.time = None

    def parse_authdata(self, authdata):
        """ parse struct EFI_VARIABLE_AUTHENTICATION_2 """
        self.parse_time(authdata, 0)
        (length, revision, certtype) = struct.unpack_from("=LHH", authdata, 16)
        guid = guids.parse_bin(authdata, 24)
        if str(guid) != guids.EfiCertPkcs7:
            raise RuntimeError('no pkcs7 signature')
        self.data = authdata [ 16 + length : ]

    def bytes_time(self):
        """ generate struct EFI_TIME """
        if self.time is None:
            return b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        return struct.pack("=HBBBBBxLhBx",
                           self.time.year, self.time.month, self.time.day,
                           self.time.hour, self.time.minute, self.time.second,
                           self.time.microsecond * 1000,
                           0, 0)

    def update_time(self, ts = None):
        if not self.attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS:
            return
        if ts is None:
            ts = datetime.datetime.now()
        if self.time is None or self.time < ts:
            self.time = ts

    def sigdb_clear(self):
        if self.sigdb is None:
            raise RuntimeError
        self.sigdb = siglist.EfiSigDB()
        self.data = bytes(self.sigdb)
        self.update_time(initial_ts)

    def sigdb_set(self, sigdb):
        self.sigdb = sigdb
        self.data = bytes(self.sigdb)
        self.update_time(self.sigdb.get_cert_ts())

    def sigdb_add_cert(self, guid, filename):
        if self.sigdb is None:
            raise RuntimeError
        self.sigdb.add_cert(guid, filename)
        self.data = bytes(self.sigdb)
        self.update_time(self.sigdb.get_cert_ts())

    def sigdb_add_hash(self, guid, hashdata):
        if self.sigdb is None:
            raise RuntimeError
        self.sigdb.add_hash(guid, hashdata)
        self.data = bytes(self.sigdb)
        self.update_time()

    def sigdb_add_dummy(self, guid):
        if self.sigdb is None:
            raise RuntimeError
        self.sigdb.add_dummy(guid)
        self.data = bytes(self.sigdb)
        self.update_time(initial_ts)

    def set_bool(self, value):
        if value:
            self.data = b'\x01'
        else:
            self.data = b'\x00'
        self.update_time()

    def set_uint32(self, value):
        self.data = value.to_bytes(4, byteorder = 'little')
        self.update_time()

    def set_boot_entry(self, attr, title, path, optdata = None):
        entry = bootentry.BootEntry(attr = attr, title = title,
                                    devicepath = path, optdata = optdata)
        self.data = bytes(entry)
        self.update_time()

    def set_boot_next(self, index):
        self.data = struct.pack('=H', index)
        self.update_time()

    def set_boot_order(self, order):
        self.data = b''
        for item in order:
            self.data += struct.pack('=H', item)
        self.update_time()

    def append_boot_order(self, index):
        self.data += struct.pack('=H', index)
        self.update_time()

    def set_from_file(self, filename):
        with open(filename, 'rb') as f:
            self.data = f.read()
        self.update_time()

    def fmt_bool(self):
        if self.data[0]:
            return 'bool: ON'
        return 'bool: off'

    def fmt_ascii(self):
        string = self.data.decode().rstrip('\0')
        string = re.sub(r'\n', r'\\n', string)
        return f'ascii: "{string}"'

    def fmt_boot_entry(self):
        entry = bootentry.BootEntry(data = self.data)
        return f'boot entry: {entry}'

    def fmt_boot_list(self):
        bootlist = []
        for pos in range(len(self.data) >> 1):
            nr = struct.unpack_from('=H', self.data, pos * 2)
            bootlist.append(f'{nr[0]:04x}')
            desc= ", ".join(bootlist)
        return f'boot order: {desc}'

    def fmt_dev_path(self):
        obj = devpath.DevicePath(self.data)
        return f'devpath: {obj}'

    # pylint: disable=too-many-return-statements
    def fmt_data(self):
        name = str(self.name)
        if name in bool_names:
            return self.fmt_bool()
        if name in ascii_names:
            return self.fmt_ascii()
        if name in blist_names:
            return self.fmt_boot_list()
        if name in dpath_names:
            return self.fmt_dev_path()
        if name.startswith('Boot0'):
            return self.fmt_boot_entry()

        if len(self.data) in (1, 2, 4, 8):
            name = {
                1 : 'byte',
                2 : 'word',
                4 : 'dword',
                8 : 'qword',
            }
            n = name[len(self.data)]
            d = bytearray(self.data)
            d.reverse()
            return f'{n}: 0x{d.hex()}'

        return None

# pylint: disable=too-many-public-methods
class EfiVarList(collections.UserDict):
    """  class for efi variable list """

    def create(self, name):
        logging.info('create variable %s', name)
        var = EfiVar(ucs16.from_string(name))
        self[name] = var
        return var

    def delete(self, name):
        if self.get(name):
            logging.info('delete variable: %s', name)
            del self[name]
        else:
            logging.warning('variable %s not found', name)

    def set_bool(self, name, value):
        var = self.get(name)
        if not var:
            var = self.create(name)
        logging.info('set variable %s: %s', name, value)
        var.set_bool(value)

    def set_uint32(self, name, value):
        var = self.get(name)
        if not var:
            var = self.create(name)
        logging.info('set variable %s: %s', name, value)
        var.set_uint32(value)


    def set_boot_entry(self, index, title, path, optdata = None):
        name = f'Boot{index:04X}'
        var = self.get(name)
        if not var:
            var = self.create(name)
        t = ucs16.from_string(title)
        logging.info('set variable %s: %s = %s', name, t, path)
        var.set_boot_entry(bootentry.LOAD_OPTION_ACTIVE,
                           t, path, optdata)

    def add_boot_entry(self, title, path, optdata = None):
        for index in range(0xffff):
            name = f'Boot{index:04X}'
            var = self.get(name)
            if not var:
                self.set_boot_entry(index, title, path, optdata)
                return index
        return None

    def set_boot_next(self, index):
        name = 'BootNext'
        var = self.get(name)
        if not var:
            var = self.create(name)
        logging.info('set variable %s: 0x%04X', name, index)
        var.set_boot_next(index)

    def append_boot_order(self, index):
        name = 'BootOrder'
        var = self.get(name)
        if not var:
            var = self.create(name)
        logging.info('append to variable %s: 0x%04X', name, index)
        var.append_boot_order(index)

    def set_from_file(self, name, filename):
        var = self.get(name)
        if not var:
            var = self.create(name)
        logging.info('set variable %s from file %s', name, filename)
        var.set_from_file(filename)


    def add_cert(self, name, owner, filename, replace = False):
        var = self.get(name)
        if not var:
            var = self.create(name)
        if replace:
            logging.info('clear %s sigdb', name)
            var.sigdb_clear()
        logging.info('add %s cert %s', name, filename)
        var.sigdb_add_cert(guids.parse_str(owner), filename)

    def add_hash(self, name, owner, hashdata):
        var = self.get(name)
        if not var:
            var = self.create(name)
        logging.info('add %s hash %s', name, hashdata)
        var.sigdb_add_hash(guids.parse_str(owner),
                           bytes.fromhex(hashdata))

    def add_dummy_dbx(self, owner):
        var = self.get('dbx')
        if var:
            return
        logging.info("add dummy dbx entry")
        var = self.create('dbx')
        var.sigdb_add_dummy(guids.parse_str(owner))


    def enable_secureboot(self):
        self.add_dummy_dbx(guids.OvmfEnrollDefaultKeys)
        self.set_bool('SecureBootEnable', True)
        self.set_bool('CustomMode', False)

    def enroll_platform_with_cert(self, cert,
                                  guid = guids.OvmfEnrollDefaultKeys):
        self.add_cert('PK', guid, cert, True)
        self.add_cert('KEK', guid, cert, True)
        self.add_cert('KEK', guids.MicrosoftVendor, certs.MS_KEK_2011, False)
        self.add_cert('KEK', guids.MicrosoftVendor, certs.MS_KEK_2023, False)
        self.add_dummy_dbx(guids.OvmfEnrollDefaultKeys)

    def enroll_platform_redhat(self):
        self.enroll_platform_with_cert(certs.REDHAT_PK)

    def enroll_platform_generate(self, name):
        pk = certs.pk_generate(cn = name)
        self.enroll_platform_with_cert(pk.name)

    def add_microsoft_keys(self):
        self.add_cert('db', guids.MicrosoftVendor, certs.MS_WIN_2011, False)
        self.add_cert('db', guids.MicrosoftVendor, certs.MS_WIN_2023, False)
        self.add_cert('db', guids.MicrosoftVendor, certs.MS_3RD_2011, False)
        self.add_cert('db', guids.MicrosoftVendor, certs.MS_3RD_2023, False)

    def add_distro_keys(self, distro):
        certlist = certs.DISTRO_CA.get(distro).get('certs')
        if not certlist:
            l = ', '.join(certs.DISTRO_CA.keys())
            raise RuntimeError(f'unknown distro: {distro} (valid: {l})')
        for item in certlist:
            self.add_cert('db', guids.OvmfEnrollDefaultKeys, item, False)


    @staticmethod
    def print_siglist(slist):
        name = guids.name(slist.guid)
        count = len(slist)
        print(f'  siglist type={name} count={count}')
        if slist.x509:
            try:
                scn = slist.x509.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
                print(f'    subject CN={scn.value}')
            except IndexError:
                print('    no subject CN')
            try:
                icn = slist.x509.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
                print(f'    issuer CN={icn.value}')
            except IndexError:
                print('    no issuer CN')
        elif str(slist.guid) == guids.EfiCertSha256:
            for sig in list(slist):
                print(f"    {sig['data'].hex()}")

    @staticmethod
    def print_hexdump(data):
        hstr = ''
        astr = ''
        pos = 0
        count = 0
        while count < len(data) and count < 256:
            hstr += f'{data[count]:02x} '
            if (data[count] > 0x20 and data[count] < 0x7f):
                astr += f'{data[count]:c}'
            else:
                astr += '.'
            count += 1

            if count % 4 == 0:
                hstr += ' '
                astr += ' '

            if count % 16 == 0 or count == len(data):
                print(f'  {pos:06x}:  {hstr:52s} {astr}')
                hstr = ''
                astr = ''
                pos += 16

        if count < len(data):
            print(f'  {pos:06x}:  [ ... ]')

    def print_normal(self, hexdump = False):
        for (key, var) in sorted(self.items()):
            name = str(var.name)
            gname = guids.name(var.guid)
            size = len(var.data)
            line = f'name={name} guid={gname} size={size}'
            if var.count:
                line += f' count={var.count}'
            if var.pkidx:
                line += f' pkidx={var.pkidx}'
            if var.time:
                line += f' time={var.time}'
            print(line)
            line = var.fmt_data()
            if line:
                print('  ' + line)
            if var.sigdb:
                for slist in var.sigdb:
                    self.print_siglist(slist)
            if hexdump:
                self.print_hexdump(var.data)
            print('')

    def print_compact(self):
        for (key, var) in sorted(self.items()):
            name = str(var.name)
            desc = var.fmt_data()
            if not desc:
                desc = f'blob: {len(var.data)} bytes'
            print(f'{name:20s}: {desc}')
