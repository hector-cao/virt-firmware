import os
import json
import argparse
import unittest
import subprocess

from virt.firmware.efi import certs
from virt.firmware.efi import efivar
from virt.firmware.efi import efijson
from virt.firmware.efi import devpath

from virt.firmware.varstore import edk2
from virt.firmware.varstore import linux
from virt.firmware.varstore import aws

from virt.firmware.bootcfg import linuxcfg
from virt.firmware.bootcfg import main as bcfgmain

VARS_EMPTY   = "/usr/share/OVMF/OVMF_VARS.fd"
VARS_SECBOOT = "/usr/share/OVMF/OVMF_VARS.secboot.fd"

TEST_DATA    = os.path.join(os.path.dirname(__file__), "data")
TEST_AWS     = os.path.join(TEST_DATA, 'secboot.aws')
TEST_DBX     = os.path.join(TEST_DATA, 'DBXUpdate-20100307.x64.bin')

cache_detect_container = None

def detect_container():
    global cache_detect_container
    if cache_detect_container is None:
        result = subprocess.run([ 'systemd-detect-virt', '--container', '--quiet' ])
        if result.returncode == 0:
            cache_detect_container = True
        else:
            cache_detect_container = False
    return cache_detect_container

class TestsEdk2(unittest.TestCase):

    @unittest.skipUnless(os.path.exists(VARS_EMPTY), 'no empty vars file')
    def test_probe_edk2_good(self):
        self.assertTrue(edk2.Edk2VarStore.probe(VARS_EMPTY))

    def test_probe_edk2_bad(self):
        self.assertFalse(edk2.Edk2VarStore.probe(TEST_AWS))

    def test_probe_aws_good(self):
        self.assertTrue(aws.AwsVarStore.probe(TEST_AWS))

    @unittest.skipUnless(os.path.exists(VARS_EMPTY), 'no empty vars file')
    def test_probe_aws_bad(self):
        self.assertFalse(aws.AwsVarStore.probe(VARS_EMPTY))

    @unittest.skipUnless(os.path.exists(VARS_EMPTY), 'no empty vars file')
    def test_enroll_microsoft(self):
        store = edk2.Edk2VarStore(VARS_EMPTY)
        varlist = store.get_varlist()
        varlist.enroll_platform_redhat()
        varlist.add_microsoft_keys()
        varlist.enable_secureboot()
        blob = store.bytes_varstore(varlist)

    @unittest.skipUnless(os.path.exists(VARS_EMPTY), 'no empty vars file')
    def test_enroll_distro(self):
        store = edk2.Edk2VarStore(VARS_EMPTY)
        varlist = store.get_varlist()
        varlist.enroll_platform_redhat()
        varlist.add_distro_keys('rhel')
        varlist.add_distro_keys('fedora')
        varlist.add_distro_keys('centos')
        varlist.enable_secureboot()
        blob = store.bytes_varstore(varlist)

    @unittest.skipUnless(os.path.exists(VARS_SECBOOT), 'no secboot vars file')
    def test_json(self):
        store = edk2.Edk2VarStore(VARS_SECBOOT)
        varlist = store.get_varlist()
        j = json.dumps(varlist, cls=efijson.EfiJSONEncoder, indent = 4)
        l = json.loads(j, object_hook = efijson.efi_decode)

    def test_add_hash(self):
        varlist = efivar.EfiVarList()
        varlist.add_hash('db', 'shim', '70183c6c50978ee60f61d8a60580d5e0022114f20f3b99715617054e916770a4')

    def test_set_boot_url(self):
        path = devpath.DevicePath.uri("http://server/path/boot.iso")
        varlist = efivar.EfiVarList()
        varlist.set_boot_entry(0x99, 'netboot', path)
        varlist.set_boot_next(0x99)

    def test_set_boot_filepath(self):
        path = devpath.DevicePath.filepath("\\EFI\\fedora\\shimx64.efi")
        varlist = efivar.EfiVarList()
        varlist.set_boot_entry(0x99, 'shim', path)
        varlist.set_boot_next(0x99)

    @unittest.skipUnless(os.path.exists('/sys/firmware/efi/efivars'), 'no efivars fs')
    def test_parse_linux(self):
        store = linux.LinuxVarStore()
        varlist = store.get_varlist()

    def test_parse_aws(self):
        varlist = aws.AwsVarStore(TEST_AWS)

    def test_generate_aws(self):
        varlist = efivar.EfiVarList()
        varlist.enroll_platform_redhat()
        varlist.add_microsoft_keys()
        varlist.enable_secureboot()
        uefidata = aws.AwsVarStore.base64_varstore(varlist)

    def test_parse_dbxupdate(self):
        with open(TEST_DBX, 'rb') as f:
            blob = f.read()
        dbx = efivar.EfiVar('dbx', authdata = blob)

    def test_generate_pk(self):
        certs.pk_generate()

    @unittest.skipIf(detect_container(), 'in container')
    @unittest.skipUnless(os.path.exists('/sys/firmware/efi/efivars'), 'no efivars fs')
    def test_add_uki(self):
        info = linuxcfg.LinuxOsInfo()
        esp  = info.esp_path()
        shim = info.shim_path()
        cfg  = linuxcfg.LinuxEfiBootConfig()
        options = argparse.Namespace(shim      = shim,
                                     title     = 'test',
                                     adduki    = f'{esp}/EFI/Linux/test.eki',
                                     cmdline   = None,
                                     bootnext  = True,
                                     bootorder = None,
                                     dryrun    = True)
        bcfgmain.add_uki(cfg, options)

if __name__ == '__main__':
    unittest.main()
