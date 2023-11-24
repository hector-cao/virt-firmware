#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" linux efivarfs varstore parser """
import os
import struct
import logging

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar

# pylint: disable=too-few-public-methods
class LinuxVarStore:
    """  class for linux efivarfs varstore """

    def __init__(self, path = '/sys/firmware/efi/efivars'):
        self.path = path
        self.scan = {}

    def scanadd(self, name, guid):
        if not self.scan.get(guid):
            self.scan[guid] = {}
        self.scan[guid][name] = True

    def scandel(self, name, guid):
        del self.scan[guid][name]

    def scandir(self):
        if self.scan:
            return
        if not os.path.isdir(self.path):
            return
        with os.scandir(self.path) as it:
            for entry in it:
                if not entry.is_file():
                    continue
                if len(entry.name) < 38:
                    continue
                name = entry.name[ : len(entry.name) - 37 ]
                guid = entry.name[ len(entry.name) - 36 : ]
                self.scanadd(name, guid)

    def get_variable(self, name, guid):
        self.scandir()
        if not self.scan.get(guid):
            return None
        if not self.scan[guid].get(name):
            return None

        filename = os.path.join(self.path, f'{name}-{guid}')
        try:
            with open(filename, "rb") as f:
                attr = int.from_bytes(f.read(4), byteorder='little', signed=False)
                data = f.read()
                var = efivar.EfiVar(ucs16.from_string(name),
                                    guid = guids.parse_str(guid),
                                    attr = attr, data = data)
            return var
        except OSError:
            return None

    def set_variable(self, var):
        filename = os.path.join(self.path, f'{var.name}-{var.guid}')
        blob = struct.pack('=L', var.attr)
        blob += var.data
        logging.info('updating %s', filename)
        with open(filename, "wb") as f:
            f.write(blob)
        self.scanadd(str(var.name), str(var.guid))

    def del_variable(self, name, guid):
        filename = os.path.join(self.path, f'{name}-{guid}')
        logging.info('removing %s', filename)
        os.unlink(filename)
        self.scandel(name, guid)

    def get_varlist(self, volatile = False):
        self.scandir()
        varlist = efivar.EfiVarList()

        logging.info('reading linux varstore from %s', self.path)
        for (guid, names) in self.scan.items():
            for name in names.keys():
                var = self.get_variable(name, guid)
                if var and (var.attr & efivar.EFI_VARIABLE_NON_VOLATILE or volatile):
                    varlist[name] = var
        return varlist
