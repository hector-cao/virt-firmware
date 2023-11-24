#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
"""
boot entry decoder

EFI_LOAD_OPTION
"""

import struct

from virt.firmware.efi import ucs16
from virt.firmware.efi import devpath


LOAD_OPTION_ACTIVE           = 0x00000001
LOAD_OPTION_FORCE_RECONNECT  = 0x00000002
LOAD_OPTION_HIDDEN           = 0x00000008

LOAD_OPTION_CATEGORY         = 0x00001F00
LOAD_OPTION_CATEGORY_BOOT    = 0x00000000
LOAD_OPTION_CATEGORY_APP     = 0x00000100


class BootEntry:
    """ class reprsenting an efi boot entry """

    # pylint: disable=too-many-arguments
    def __init__(self, data = None,
                 attr = None, title = None, devicepath = None, optdata = None):
        self.attr = None
        self.title = None
        self.devicepath = None
        self.optdata = None
        if data:
            self.parse(data)
        if attr:
            self.attr = attr
        if title:
            self.title = title
        if devicepath:
            self.devicepath = devicepath
        if optdata:
            self.optdata = optdata

    def parse(self, data):
        (self.attr, pathsize) = struct.unpack_from('=LH', data)
        self.title = ucs16.from_ucs16(data, 6)
        path = data[ self.title.size() + 6 :
                     self.title.size() + 6 + pathsize ]
        self.devicepath = devpath.DevicePath(path)
        optdata = data[ self.title.size() + 6 + pathsize : ]
        if len(optdata):
            self.optdata = optdata

    def __bytes__(self):
        blob = b''
        pathdata = bytes(self.devicepath)
        blob += struct.pack('=LH', self.attr, len(pathdata))
        blob += bytes(self.title)
        blob += pathdata
        if self.optdata:
            blob += self.optdata
        return blob

    def __str__(self):
        string = f'title="{self.title}" devpath={self.devicepath}'
        if self.optdata:
            string += f' optdata={self.optdata.hex()}'
        return string
