#!/usr/bin/python
""" calculate efi variable measurements -- EXPERIMENTAL """
import sys
import json
import hashlib
import logging
import optparse
import collections

from virt.firmware import dump
from virt.firmware.efi import ucs16
from virt.firmware.efi import guids
from virt.firmware.efi import efivar
from virt.firmware.varstore import aws
from virt.firmware.varstore import edk2


########################################################################
# pcr calculation

class PCR:
    """ tpm2 pcr register """

    def __init__(self):
        self.banks = {
            'sha1'   : bytes(160 >> 3),
            'sha256' : bytes(256 >> 3),
            'sha384' : bytes(384 >> 3),
            'sha512' : bytes(512 >> 3),
        }

    def extend_hash(self, bank, hashdata):
        h = hashlib.new(bank)
        h.update(self.banks[bank])
        h.update(hashdata)
        self.banks[bank] = h.digest()

    def value(self, bank):
        return self.banks[bank]

def calculate_pcrs(banks, result):
    pcrs = {}
    for item in result:
        index = item['pcr']
        pcr = pcrs.get(index)
        if not pcr:
            pcr = PCR()
            pcrs[index] = pcr
        for digest in item['digests']:
            bank = digest['hashAlg']
            pcr.extend_hash(bank, bytes.fromhex(digest['digest']))

    values = []
    for index in sorted(pcrs.keys()):
        pcr = pcrs.get(index)
        for bank in banks:
            values.append({
                'pcr'     : index,
                'hashAlg' : bank,
                'digest'  : pcr.value(bank).hex()
            })
    return values

def pcr_used(nr, result):
    for evt in result:
        if evt['pcr'] == nr:
            return True
    return False


########################################################################
# measure misc

def hash_digest(banks, hashdata):
    result = []
    for bank in banks:
        h = hashlib.new(bank)
        h.update(hashdata)
        result.append({
            'hashAlg' : bank,
            'digest'  : h.hexdigest()
        })
    return result

def measure_sep(index, banks):
    separator = bytes(4)
    result = {
        'pcr'          : index,
        'digests'      : hash_digest(banks, separator),
        'content_type' : 'pcclient_std',
        'content'      : {
            'event_type' : 'EV_SEPARATOR',
            'event_data' : separator.hex(),
        }
    }
    return result


########################################################################
# measure vars

def measure_var(banks, var, cfg):
    namelen = len(var.name.data) >> 1
    datalen = len(var.data)

    varlog = b''
    varlog += var.guid.bytes_le
    varlog += namelen.to_bytes(8, byteorder = 'little')
    varlog += datalen.to_bytes(8, byteorder = 'little')
    varlog += var.name.data
    varlog += var.data

    if cfg:
        evttype = 'EV_EFI_VARIABLE_DRIVER_CONFIG'
    else:
        evttype = 'EV_EFI_VARIABLE_AUTHORITY'

    result = {
        'pcr'          : 7,
        'digests'      : hash_digest(banks, varlog),
        'content_type' : 'pcclient_std',
        'content'      : {
            'event_type' : evttype,
            'event_data' : varlog.hex(),
        },
    }
    return result

def measure_varlist_shim(banks, varlist):
    result = []

    result.append(measure_sep(7, banks))

    var = varlist.get('SbatLevel')
    if var:
        result.append(measure_var(banks, var, False))

    sb = efivar.EfiVar(ucs16.from_string('MokListTrusted'))
    sb.set_bool(True)
    result.append(measure_var(banks, sb, False))
    return result

def measure_varlist(banks, varlist,
                    secureboot = True,
                    shim = False):
    result = []

    sb = efivar.EfiVar(ucs16.from_string('SecureBoot'))
    sb.set_bool(secureboot)
    result.append(measure_var(banks, sb, True))

    for name in ('PK', 'KEK', 'db', 'dbx'):
        var = varlist.get(name)
        if var:
            result.append(measure_var(banks, var, True))

    if shim:
        result += measure_varlist_shim(banks, varlist)

    return result


########################################################################
# measure code

def measure_version(banks, version):
    ustr = ucs16.from_string(version)
    result = {
        'pcr'          : 0,
        'digests'      : hash_digest(banks, bytes(ustr)),
        'content_type' : 'pcclient_std',
        'content'      : {
            'event_type' : 'EV_S_CRTM_VERSION',
            'event_data' : bytes(ustr).hex(),
        },
    }
    return result

def find_volume(item, nameguid = None, typeguid = None):
    if isinstance(item, dump.Edk2Volume):
        if nameguid and item.name and str(item.name) == nameguid:
            return item
        if typeguid and item.guid and str(item.guid) == typeguid:
            return item
    if isinstance(item, collections.UserList):
        for i in list(item):
            r = find_volume(i, nameguid, typeguid)
            if r:
                return r
    return None

def measure_volume(banks, name, vol):
    result = {
        'pcr'          : 0,
        'digests'      : hash_digest(banks, vol.blob),
        'content_type' : 'pcclient_std',
        'content'      : {
            'event_type' : 'EV_EFI_PLATFORM_FIRMWARE_BLOB',
            'event_data' : (vol.base.to_bytes(length = 8, byteorder = 'little').hex() +
                            vol.tlen.to_bytes(length = 8, byteorder = 'little').hex()),
        },
    }
    return result

def measure_image(banks, image, version = None):
    result = []
    peifv = find_volume(image, nameguid = guids.OvmfPeiFv)
    dxefv = find_volume(image, nameguid = guids.OvmfDxeFv)
    varfv = find_volume(image, typeguid = guids.NvData)

    if (peifv or dxefv) and version:
        result.append(measure_version(banks, version))
    if peifv:
        peifv.base = 0x820000
        result.append(measure_volume(banks, 'PEIFV', peifv))
    if dxefv:
        dxefv.base = 0x900000
        result.append(measure_volume(banks, 'DXEFV', dxefv))

    if varfv:
        edk2store = edk2.Edk2VarStore(image.name)
        varlist = edk2store.get_varlist()
        result += measure_varlist(banks, varlist)

    return result


########################################################################
# main

def main():
    parser = optparse.OptionParser()
    parser.add_option('-l', '--loglevel', dest = 'loglevel', type = 'string', default = 'warn',
                      help = 'set loglevel to LEVEL', metavar = 'LEVEL')

    parser.add_option('--image', dest = 'image', type = 'string',
                      help = 'read edk2 image from FILE', metavar = 'FILE')
    parser.add_option('--version', dest = 'version', type = 'string',
                      help = 'firmware version (PcdFirmwareVersionString)', metavar = 'VER')

    parser.add_option('--pcrlock', dest = 'pcrlock',
                      action = 'store_true', default = False,
                      help = 'write event log in systemd-pcrlock format (default)')
    parser.add_option('--digests', dest = 'digests',
                      action = 'store_true', default = False,
                      help = 'write expected pcr values')

    parser.add_option('--vars', dest = 'vars', type = 'string',
                      help = 'read edk2 vars from FILE', metavar = 'FILE')
    parser.add_option('--no-sb', '--no-secure-boot', dest = 'secureboot',
                      action = 'store_false', default = True,
                      help = 'assume secure boot is disabled')
    parser.add_option('--shim', dest = 'shim',
                      action = 'store_true', default = False,
                      help = 'enable shim variable measurements')
    parser.add_option('--no-shim', dest = 'shim',
                      action = 'store_false',
                      help = 'disable shim variable measurements')

    parser.add_option('--bank', dest = 'banks',
                      action = 'append', type = 'string',
                      help = 'pick tpm2 banks (sha1, sha256, sha384, sha512),'
                      ' specify multiple times to select more than one')

    (options, args) = parser.parse_args()
    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))
    # defaults
    if not options.banks:
        options.banks = [ 'sha256', ]

    if not options.pcrlock and not options.digests:
        options.pcrlock = True

    # generate event log
    eventlog = []
    if options.image:
        with open(options.image, 'rb') as f:
            data = f.read()
        data = dump.unqcow2(options.image, data)
        image = dump.Edk2Image(options.image, data)
        eventlog = measure_image(options.banks, image, options.version)

    elif options.vars:
        if edk2.Edk2VarStore.probe(options.vars):
            edk2store = edk2.Edk2VarStore(options.vars)
            varlist = edk2store.get_varlist()
        elif edk2.Edk2VarStoreQcow2.probe(options.vars):
            edk2store = edk2.Edk2VarStoreQcow2(options.vars)
            varlist = edk2store.get_varlist()
        elif aws.AwsVarStore.probe(options.vars):
            awsstore = aws.AwsVarStore(options.vars)
            varlist = awsstore.get_varlist()
        else:
            logging.error("unknown input file format")
            return 1
        eventlog = measure_varlist(options.banks, varlist,
                                   secureboot = options.secureboot,
                                   shim = options.shim)

    # print results
    result = {}
    if options.pcrlock:
        result['records'] = eventlog
    elif options.digests:
        if pcr_used(0, eventlog):
            # add 500-separator.pcrlock
            eventlog.append(measure_sep(0, options.banks))
        result['values'] = calculate_pcrs(options.banks, eventlog)
    print(json.dumps(result, indent = 4))

    return 0

if __name__ == '__main__':
    sys.exit(main())
