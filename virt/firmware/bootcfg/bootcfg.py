#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
# pylint: disable=too-many-instance-attributes,consider-iterating-dictionary
""" core EfiBootConfig class to manage boot configuration """
import re
import struct

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import bootentry

from virt.firmware.varstore import aws
from virt.firmware.varstore import edk2

class EfiBootConfig:
    """ efi boot configuration """

    def __init__(self):
        self.bootorder   = None
        self.bootcurrent = None
        self.bootnext    = None
        self.bcurr = None  # parsed BootCurrent
        self.bnext = None  # parsed BootNext
        self.blist = []    # parsed BootOrder
        self.unused = []   # unused BootNNNN entry list
        self.bentr = {}    # parsed BootNNNN entries
        self.bnext_updated = False
        self.blist_updated = False

    def parse_boot_variables(self):
        if self.bootorder:
            self.blist = []
            for pos in range(len(self.bootorder.data) >> 1):
                nr = struct.unpack_from('=H', self.bootorder.data, pos * 2)
                self.blist.append(nr[0])
                self.bentr[nr[0]] = None
        if self.bootcurrent:
            nr = struct.unpack_from('=H', self.bootcurrent.data)
            self.bcurr = nr[0]
            self.bentr[nr[0]] = None
        if self.bootnext:
            nr = struct.unpack_from('=H', self.bootnext.data)
            self.bnext = nr[0]
            self.bentr[nr[0]] = None

    def add_unused_entries(self, names):
        regex = re.compile('Boot([0-9A-Z]{4})')
        for name in names:
            result = regex.match(name)
            if not result:
                continue
            nr = int(result.group(1), 16)
            if nr in self.bentr:
                continue
            self.unused.append(nr)
            self.bentr[nr] = None

    @staticmethod
    def print_optdata(prefix, optdata):
        if len(optdata) >= 4 and optdata[0] != 0 and optdata[1] == 0:
            print(f'{prefix} opt/ucs16: {ucs16.from_ucs16(optdata, 0)}')
        elif len(optdata) == 16:
            print(f'{prefix} opt/guid: {guids.parse_bin(optdata, 0)}')
        else:
            print(f'{prefix} opt/hex: {optdata.hex()}')

    def print_entry(self, nr, verbose):
        entry = self.bentr[nr]
        cstr = 'C' if nr == self.bcurr else ' '
        nstr = 'N' if nr == self.bnext else ' '
        ostr = 'O' if nr in self.blist else ' '
        if not entry:
            print(f'# {cstr} {nstr} {ostr}  -  {nr:04x}  -  [ missing ]')
            return
        print(f'# {cstr} {nstr} {ostr}  -  {nr:04x}  -  {entry.title}')
        if verbose:
            prefix = '#                    ->'
            print(f'{prefix} path: {entry.devicepath}')
            if entry.optdata:
                self.print_optdata(prefix, entry.optdata)
            print('#')

    def print_cfg(self, verbose = False):
        print('# C - BootCurrent, N - BootNext, O - BootOrder')
        print('# --------------------------------------------')
        if self.bcurr is not None and not self.bcurr in self.blist:
            self.print_entry(self.bcurr, verbose)
        if self.bnext is not None and not self.bnext in self.blist and self.bcurr != self.bnext:
            self.print_entry(self.bnext, verbose)
        for nr in self.blist:
            self.print_entry(nr, verbose)
        for nr in self.unused:
            self.print_entry(nr, verbose)

    def find_uki_entry(self, uki):
        for (nr, entry) in self.bentr.items():
            if not entry or not entry.optdata:
                continue
            optpath = str(ucs16.from_ucs16(entry.optdata, 0)).strip()
            if optpath == str(uki):
                return nr
        return None

    def find_title_entry(self, title):
        for (nr, entry) in self.bentr.items():
            if not entry:
                continue
            if str(entry.title) == str(title):
                return nr
        return None

    def find_devpath_entry(self, devicepath):
        blob = bytes(devicepath)
        for (nr, entry) in self.bentr.items():
            if blob == bytes(entry.devicepath):
                return nr
        return None

    def find_unused_entry(self):
        nr = 0
        while nr in self.bentr:
            nr += 1
        return nr

    def add_entry(self, entry):
        nr = self.find_unused_entry()
        self.bentr[nr] = entry
        self.unused.append(nr)
        return nr

    def get_entry(self, nr):
        if nr >= len(self.bentr):
            return None
        return self.bentr[nr]

    def remove_entry(self, nr):
        del self.bentr[nr]
        if nr == self.bnext:
            self.bnext = None
            self.bnext_updated = True
        if nr in self.blist:
            self.blist = list(filter(lambda x: x != nr, self.blist))
            self.blist_updated = True
        if nr in self.unused:
            self.unused = list(filter(lambda x: x != nr, self.unused))

    def set_boot_next(self, nr):
        self.bnext = nr
        self.bnext_updated = True
        if nr in self.unused:
            self.unused = list(filter(lambda x: x != nr, self.unused))

    def set_boot_order(self, nr, pos):
        self.blist = list(filter(lambda x: x != nr, self.blist))
        self.blist.insert(pos, nr)
        self.blist_updated = True
        if nr in self.unused:
            self.unused = list(filter(lambda x: x != nr, self.unused))


class VarStoreEfiBootConfig(EfiBootConfig):
    """ read efi boot configuration from varstore  """

    def __init__(self, filename):
        super().__init__()
        self.varstore = None
        self.varlist  = None
        self.varstore_init(filename)

    def varstore_init(self, filename):
        if edk2.Edk2VarStore.probe(filename):
            self.varstore = edk2.Edk2VarStore(filename)
        elif edk2.Edk2VarStoreQcow2.probe(filename):
            self.varstore = edk2.Edk2VarStoreQcow2(filename)
        elif aws.AwsVarStore.probe(filename):
            self.varstore = aws.AwsVarStore(filename)
        else:
            return

        self.varlist = self.varstore.get_varlist()
        self.bootcurrent = None
        self.bootorder = self.varlist.get('BootOrder')
        self.bootnext = self.varlist.get('BootNext')
        self.parse_boot_variables()
        self.add_unused_entries(self.varlist.keys())
        for nr in self.bentr.keys():
            var = self.varlist.get(f'Boot{nr:04X}')
            if var:
                self.bentr[nr] = bootentry.BootEntry(data = var.data)
