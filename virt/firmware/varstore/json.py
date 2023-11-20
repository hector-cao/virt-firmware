#!/usr/bin/python
""" linux efivarfs varstore parser """
import os
import json
import struct
import logging

from virt.firmware.efi import efijson

class JsonVarStore:
    """  class for json varstore """

    def __init__(self, filename = None):
        self.filename = filename
        self.variables = {}
        if self.filename:
            self.parse()

    @staticmethod
    def probe(filename):
        with open(filename, "r", encoding = 'utf-8') as f:
            try:
                j = json.loads(f.read())
                return True
            except json.decoder.JSONDecodeError:
                return False

    def parse(self):
        logging.info('reading json varstore from %s', self.filename)
        with open(self.filename, "r", encoding = 'utf-8') as f:
            self.variables = json.loads(f.read(), object_hook = efijson.efi_decode)

    def get_varlist(self):
        return self.variables

    @staticmethod
    def json_varstore(varlist):
        return json.dumps(varlist, cls = efijson.EfiJSONEncoder, indent = 4)

    @staticmethod
    def write_varstore(filename, varlist):
        logging.info('writing json varstore to %s', filename)
        j = JsonVarStore.json_varstore(varlist)
        with open(filename, "w", encoding = 'utf-8') as f:
            f.write(j)
