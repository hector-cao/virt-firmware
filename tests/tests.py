import os
import json
import unittest

from virt.firmware.efi import efivar
from virt.firmware.efi import efijson

from virt.firmware.varstore import edk2
from virt.firmware.varstore import linux
from virt.firmware.varstore import aws

VARS_EMPTY   = "/usr/share/OVMF/OVMF_VARS.fd"
VARS_SECBOOT = "/usr/share/OVMF/OVMF_VARS.secboot.fd"

TEST_DATA    = os.path.join(os.path.dirname(__file__), "data")
TEST_AWS     = os.path.join(TEST_DATA, 'secboot.aws')

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
    def test_enroll(self):
        store = edk2.Edk2VarStore(VARS_EMPTY)
        varlist = store.get_varlist()
        varlist.enroll_platform_redhat()
        varlist.add_microsoft_keys()
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

    @unittest.skipUnless(os.path.exists('/sys/firmware/efi/efivars'), 'no efivars fs')
    def test_parse_linux(self):
        varlist = linux.LinuxVarStore.get_varlist()

    def test_parse_aws(self):
        varlist = aws.AwsVarStore(TEST_AWS)

if __name__ == '__main__':
    unittest.main()
