#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" edk2 varstore parser """
import sys
import struct
import logging
import tempfile
import subprocess

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar

class Edk2VarStore:
    """  class for edk2 efi varstore, raw image """

    def __init__(self, filename):
        self.filename = filename
        self.filedata = b''
        self.start    = None
        self.end      = None

        self.readfile()
        self.parse_volume()

    @staticmethod
    def find_nvdata(data):
        offset = 0
        while offset + 64 < len(data):
            guid = guids.parse_bin(data, offset + 16)
            if str(guid) == guids.NvData:
                return offset
            if str(guid) == guids.Ffs:
                (tlen, sig) = struct.unpack_from('<QL', data, offset + 32)
                offset += tlen
                continue
            offset += 1024
        return None

    @staticmethod
    def probe(filename):
        with open(filename, "rb") as f:
            data = f.read()
        offset = Edk2VarStore.find_nvdata(data)
        if offset is None:
            return False
        return True

    def readfile(self):
        logging.info('reading raw edk2 varstore from %s', self.filename)
        with open(self.filename, "rb") as f:
            self.filedata = f.read()

    def parse_volume(self):
        offset = self.find_nvdata(self.filedata)
        if offset is None:
            logging.error('%s: varstore not found', self.filename)
            sys.exit(1)
        guid = guids.parse_bin(self.filedata, offset + 16)
        (vlen, sig, attr, hlen, csum, xoff, rev, blocks, blksize) = \
            struct.unpack_from("=QLLHHHxBLL", self.filedata, offset + 32)
        logging.debug('vol=%s vlen=0x%x rev=%d blocks=%d*%d (0x%x)',
                      guids.name(guid), vlen, rev,
                      blocks, blksize, blocks * blksize)
        if sig != 0x4856465f:
            logging.error('%s: not a firmware volume', self.filename)
            sys.exit(1)
        if str(guid) != guids.NvData:
            logging.error('%s: not a variable store', self.filename)
            sys.exit(1)
        return self.parse_varstore(offset + hlen)

    def parse_varstore(self, start):
        guid = guids.parse_bin(self.filedata, start)
        (size, storefmt, state) = struct.unpack_from("=LBB", self.filedata, start + 16)
        logging.debug('varstore=%s size=0x%x format=0x%x state=0x%x',
                      guids.name(guid), size, storefmt, state)
        if str(guid) != guids.AuthVars:
            logging.error('%s: unknown varstore guid', self.filename)
            sys.exit(1)
        if storefmt != 0x5a:
            logging.error('%s: unknown varstore format', self.filename)
            sys.exit(1)
        if state != 0xfe:
            logging.error('%s: unknown varstore state', self.filename)
            sys.exit(1)

        self.start = start + 16 + 12
        self.end   = start + size
        logging.info('var store range: 0x%x -> 0x%x', self.start, self.end)

    def get_varlist(self):
        pos = self.start
        varlist = efivar.EfiVarList()
        while pos < self.end:
            (magic, state, attr, count) = struct.unpack_from("=HBxLQ", self.filedata, pos)
            if magic != 0x55aa:
                break
            (pk, nsize, dsize) = struct.unpack_from("=LLL", self.filedata, pos + 32)

            if state == 0x3f:
                var = efivar.EfiVar(ucs16.from_ucs16(self.filedata, pos + 44 + 16),
                                    guid = guids.parse_bin(self.filedata, pos + 44),
                                    attr = attr,
                                    data = self.filedata[ pos + 44 + 16 + nsize :
                                                          pos + 44 + 16 + nsize + dsize],
                                    count = count,
                                    pkidx = pk)
                var.parse_time(self.filedata, pos + 16)
                varlist[str(var.name)] = var

            pos = pos + 44 + 16 + nsize + dsize
            pos = (pos + 3) & ~3 # align
        return varlist

    @staticmethod
    def bytes_var(var):
        blob = struct.pack("=HBxLQ",
                           0x55aa, 0x3f,
                           var.attr,
                           var.count)
        blob += var.bytes_time()
        blob += struct.pack("=LLL",
                            var.pkidx,
                            var.name.size(),
                            len(var.data))
        blob += var.guid.bytes_le
        blob += bytes(var.name)
        blob += var.data
        while len(blob) & 3:
            blob += b'\xff'
        return blob

    def bytes_varlist(self, varlist):
        blob = b''
        for (key, item) in sorted(varlist.items()):
            blob += self.bytes_var(item)
        if len(blob) > self.end - self.start:
            logging.error("varstore is too small")
            sys.exit(1)
        return blob

    def bytes_varstore(self, varlist):
        blob = self.filedata[ : self.start ]
        blob += self.bytes_varlist(varlist)
        for i in range(self.end - len(blob)):
            blob += b'\xff'
        blob += self.filedata[ self.end : ]
        return blob

    def write_varstore(self, filename, varlist):
        logging.info('writing raw edk2 varstore to %s', filename)
        blob = self.bytes_varstore(varlist)
        with open(filename, "wb") as f:
            f.write(blob)

class Edk2VarStoreQcow2(Edk2VarStore):
    """  class for edk2 efi varstore, qcow2 image """

    @staticmethod
    def probe(filename):
        with open(filename, "rb") as f:
            header = f.read(64)
        (magic, version, boff, bsize, mtime, size) = struct.unpack_from('>LLQLLQ', header)
        if magic != 0x514649fb:
            return False
        if size > 1024 * 1024 * 256:
            return False
        return True

    def readfile(self):
        logging.info('reading qcow2 edk2 varstore from %s', self.filename)
        with tempfile.NamedTemporaryFile() as rawfile:
            cmdline = [ 'qemu-img', 'convert',
                        '-f', 'qcow2', '-O', 'raw',
                        self.filename, rawfile.name ]
            subprocess.run(cmdline, check = True)
            self.filedata = rawfile.read()

    def write_varstore(self, filename, varlist):
        logging.info('writing qcow2 edk2 varstore to %s', filename)
        blob = self.bytes_varstore(varlist)
        with tempfile.NamedTemporaryFile() as rawfile:
            rawfile.write(blob)
            rawfile.flush()
            cmdline = [ 'qemu-img', 'convert',
                        '-f', 'raw', '-O', 'qcow2',
                        '-o', 'cluster_size=4096', '-S', '4096',
                        rawfile.name, filename ]
            subprocess.run(cmdline, check = True)
