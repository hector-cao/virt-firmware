#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" autodetect varstore format, using the probe method """

from virt.firmware.varstore import aws
from virt.firmware.varstore import edk2
from virt.firmware.varstore import jstore

def open_varstore(filename):
    if edk2.Edk2VarStoreQcow2.probe(filename):
        return edk2.Edk2VarStoreQcow2(filename)

    if edk2.Edk2VarStore.probe(filename):
        return edk2.Edk2VarStore(filename)

    if aws.AwsVarStore.probe(filename):
        return aws.AwsVarStore(filename)

    if jstore.JsonVarStore.probe(filename):
        return jstore.JsonVarStore(filename)

    return None
