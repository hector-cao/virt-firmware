#!/usr/bin/python
#
# based on pyuefivars which is:
#   Copyright Amazon.com, Inc.
#   SPDX-License-Identifier: MIT
#
###################################################################################
#
#
# variable store
#
# - ?
# - 'EFI_NV'    (6)
# - ?           (6)
# - 'VMWNVRAM'  (8)
# - ?           (4)
# - totalsize   (4)
#
#
# variable entry
#
# - guid        (16)
# - attributes  (4)
# - entrysize   (4)
# - namesize    (4)
# - name        (namesize)
# - data        (entrysize - namesize)
#
#
""" vmware nvram varstore parser """
import struct
import logging
import argparse

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar

from virt.firmware.varstore import jstore

class VmwareVarStore:
    """  class for vmware nvram varstore """

    def __init__(self, filename = None):
        self.filename = filename
        self.filedata = b''

        if self.filename:
            self.readfile()

    @staticmethod
    def probe(filename):
        with open(filename, "rb") as f:
            data = f.read()
        if b'VMWNVRAM' in data:
            return True
        return False

    def readfile(self):
        logging.info('reading vmware varstore from %s', self.filename)
        with open(self.filename, "rb") as f:
            self.filedata = f.read()

    def get_varlist(self):
        varlist = efivar.EfiVarList()
        start = self.filedata.find(b'VMWNVRAM')

        (unknown, totalsize) = struct.unpack_from('<LL', self.filedata, start + 8)
        logging.debug('totalsize=%d', totalsize)
        offset = 16

        while offset + 24 < totalsize:
            guid = guids.parse_bin(self.filedata, start + offset)
            (attr, entrysize, namesize) = struct.unpack_from('<LLL', self.filedata,
                                                             start + offset + 16)
            name = ucs16.from_ucs16(self.filedata, start + offset + 16 + 12)
            data = self.filedata [ start + offset + 16 + 12 + namesize :
                                   start + offset + 16 + 12 + entrysize ]
            logging.debug('  %-16s - attr=0x%02x entrysize=%d', name, attr, entrysize)

            if attr & 0x20:
                # 40 bytes additioal metadata, skip for now.
                var = efivar.EfiVar(name, guid = guid, attr = attr, data = data[40:])
            else:
                var = efivar.EfiVar(name, guid = guid, attr = attr, data = data)

            varlist[str(var.name)] = var
            offset += 16 + 12 + entrysize

        return varlist

    @staticmethod
    def write_varstore(filename, varlist):
        raise RuntimeError('writing vmware varstores is not supported')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', dest = 'infile', type = str, default = "tests/data/esx7.nvram")
    parser.add_argument('--out-json', dest = 'outfile', type = str)
    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = logging.DEBUG)

    if VmwareVarStore.probe(options.infile):
        vmwarestore = VmwareVarStore(options.infile)
        vl = vmwarestore.get_varlist()
        vl.print_normal()
        if options.outfile:
            jstore.JsonVarStore.write_varstore(options.outfile, vl)
