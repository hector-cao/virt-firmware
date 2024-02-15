#!/usr/bin/python
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" efi x509 certificates """
import datetime
import tempfile

from pkg_resources import resource_filename

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# redhat: PK + KEK key
REDHAT_PK = resource_filename('virt.firmware', 'certs/RedHatSecureBootPKKEKkey1.pem')

# microsoft: KEK key
MS_KEK = resource_filename('virt.firmware', 'certs/MicrosoftCorporationKEKCA2011.pem')

# microsoft: used to sign windows
MS_WIN = resource_filename('virt.firmware', 'certs/MicrosoftWindowsProductionPCA2011.pem')

# microsoft: used to sign 3rd party binaries (shim.efi, drivers).
MS_3RD = resource_filename('virt.firmware', 'certs/MicrosoftCorporationUEFICA2011.pem')

# linux distro ca keys
DISTRO_CA = {
    #
    # microsoft keys
    #
    'windows' : {
        'desc'  : 'Microsoft Windows',
        'certs' : [
            MS_WIN,
        ],
    },
    'ms-uefi' : {
        'desc'  : 'Microsoft UEFI CA',
        'certs' : [
            MS_3RD,
        ],
    },

    #
    # redhat / rhel keys
    #
    'rhel-2014' : {
        'desc'  : 'Red Hat Enterprise Linux (obsoleted by 2020 signing key rotation)',
        'certs' : [
            resource_filename('virt.firmware', 'certs/RedHatSecureBootCA3.pem'),
        ],
    },
    'rhel' : {
        'desc'  : 'Red Hat Enterprise Linux',
        'certs' : [
            resource_filename('virt.firmware', 'certs/RedHatSecureBootCA5.pem'),
            resource_filename('virt.firmware', 'certs/RedHatSecureBootCA8.pem'),
    ],
    },
    'rh-uefi' : {
        'desc'  : 'Red Hat UEFI CA',
        'certs' : [
            resource_filename('virt.firmware', 'certs/RedHatUEFICA2023.pem'),
        ],
    },

    #
    # fedora keys
    #
    'fedora' : {
        'desc'  : 'Fedora Linux',
        'certs' : [
            resource_filename('virt.firmware', 'certs/fedoraca-20200709.pem'),
        ],
    },

    #
    # centos keys
    #
    'centos-2018' : {
        'desc'  : 'CentOS Stream (obsoleted by 2020 signing key rotation)',
        'certs' : [
            resource_filename('virt.firmware', 'certs/CentOSSecureBootCAkey1.pem'),
        ],
    },
    'centos' : {
        'desc'  : 'CentOS Stream',
        'certs' : [
            resource_filename('virt.firmware', 'certs/CentOSSecureBootCA2.pem'),
        ],
    },
}

def list_distros():
    print('known distro certs:')
    for (key, val) in DISTRO_CA.items():
        print(f'  {key:12s} - {val["desc"]}')

def pk_generate(cn = 'random secure boot platform',
                org = None, city = None, state = None, country = None):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    attrs = [
        x509.NameAttribute(x509.NameOID.COMMON_NAME, cn),
    ]
    if org:
        attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, org))
    if city:
        attrs.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, city))
    if state:
        attrs.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state))
    if country:
        attrs.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country))

    subject = issuer = x509.Name(attrs)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days = 365 * 10)
    ).add_extension(
        x509.BasicConstraints(ca = False, path_length = None),
        critical = False,
    ).sign(key, hashes.SHA256())

    # pylint: disable=consider-using-with
    tf = tempfile.NamedTemporaryFile()
    tf.write(cert.public_bytes(serialization.Encoding.PEM))
    tf.flush()
    return tf
