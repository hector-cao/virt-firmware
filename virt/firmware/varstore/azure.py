#!/usr/bin/python
""" azure support """
import json
import base64
import logging

from virt.firmware.efi import guids
from virt.firmware.efi import ucs16
from virt.firmware.efi import efivar
from virt.firmware.efi import siglist

class AzureDiskTemplate:
    """ handle uefiSettings in disk templates """

    def __init__(self, filename = None):
        self.filename = filename
        self.filejson = None

        if self.filename:
            self.readfile()

    @staticmethod
    def probe(filename):
        try:
            with open(filename, "r", encoding = 'utf-8') as f:
                j = json.loads(f.read())
            if j['type'] == 'Microsoft.Compute/disks':
                return True
            return False
        except: # pylint: disable=bare-except
            return False

    def readfile(self):
        logging.info('reading azure disk template from %s', self.filename)
        with open(self.filename, "rb") as f:
            self.filejson = json.loads(f.read())

    def append_siglist(self, sdb, data):
        ownerguid = guids.parse_str(guids.MicrosoftVendor)
        if data['type'] == 'x509':
            typeguid = guids.parse_str(guids.EfiCertX509)
            for item in data['value']:
                sl = siglist.EfiSigList(guid = typeguid)
                der = base64.b64decode(item)
                sl.add_sig(ownerguid, der)
                sdb.append(sl)
        elif data['type'] == 'sha256':
            typeguid = guids.parse_str(guids.EfiCertSha256)
            sl = siglist.EfiSigList(guid = typeguid)
            for sha256 in data['value']:
                sl.add_sig(ownerguid, base64.b64decode(sha256))
            sdb.append(sl)

    def get_sigdb(self, data):
        sdb = siglist.EfiSigDB()
        if isinstance(data, dict):
            self.append_siglist(sdb, data)
        else:
            for item in data:
                self.append_siglist(sdb, item)
        return sdb

    def get_varlist(self):
        varlist = efivar.EfiVarList()
        us = self.filejson['properties']['uefiSettings']
        if us.get('signatures'):
            for (name, data) in us.get('signatures').items():
                var = efivar.EfiVar(ucs16.from_string(name))
                var.sigdb_set(self.get_sigdb(data))
                varlist[str(var.name)] = var
        for (name, data) in us.items():
            if not isinstance(data, dict):
                continue
            guid  = data.get('guid')
            attr  = data.get('attributes')
            value = data.get('value')
            if guid and attr and value:
                var = efivar.EfiVar(ucs16.from_string(name),
                                    guid = guids.parse_bin(base64.b64decode(guid), 0),
                                    attr = int.from_bytes(base64.b64decode(attr),
                                                          byteorder='little'),
                                    data = base64.b64decode(value))
                varlist[str(var.name)] = var
        return varlist


    @staticmethod
    def json_siglist(sl):
        ret = {}
        if str(sl.guid) == guids.EfiCertX509:
            ret['type'] = 'x509'
        if str(sl.guid) == guids.EfiCertSha256:
            ret['type'] = 'sha256'
        ret['value'] = []
        for item in sl:
            b64 = base64.b64encode(item['data']).decode()
            ret['value'].append(b64)
        return ret

    @staticmethod
    def json_variable(var):
        guid  = base64.b64encode(var.guid.bytes_le)
        attr  = base64.b64encode(var.attr.to_bytes(1, byteorder='little'))
        value = base64.b64encode(var.data)
        return {
            'guid'       : guid.decode(),
            'attributes' : attr.decode(),
            'value'      : value.decode(),
        }

    @staticmethod
    def json_uefisettings(varlist):
        sigs = {}
        us = {}
        for (name, var) in varlist.items():
            if name == 'PK':
                sigs[name] = AzureDiskTemplate.json_siglist(var.sigdb[0])
            elif name in ('KEK', 'db', 'dbx'):
                sigs[name] = []
                for item in var.sigdb:
                    sigs[name].append(AzureDiskTemplate.json_siglist(item))
            else:
                us[name] = AzureDiskTemplate.json_variable(var)
        if len(sigs):
            us['signatureMode'] = 'Replace'
            us['signatures'] = sigs
        return us

    @staticmethod
    def json_varstore(varlist):
        us = AzureDiskTemplate.json_uefisettings(varlist)
        ret = {
            'type' : 'Microsoft.Compute/disks',
            'properties' : {
                'uefiSettings' : us,
            },
        }
        return ret

    @staticmethod
    def write_varstore(filename, varlist):
        j = AzureDiskTemplate.json_varstore(varlist)
        logging.info('writing azure disk template to %s', filename)
        with open(filename, "w", encoding = 'utf-8') as f:
            f.write(json.dumps(j, indent = 4))


if __name__ == "__main__":
    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = logging.DEBUG)

    testfile = "tests/data/MicrosoftUEFICertificateAuthority_Template.json"
    if AzureDiskTemplate.probe(testfile):
        # test parser
        tmpl = AzureDiskTemplate(testfile)
        vl = tmpl.get_varlist()
        vl.print_normal()

        # test generator
        print('---')
        print(json.dumps(tmpl.json_varstore(vl), indent = 4))
