#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" pe (efi) binary utilities """
import sys
import gzip
import struct
import argparse

import pefile

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from virt.firmware.efi import guids
from virt.firmware.varstore import linux

from virt.peutils import pesign
from virt.peutils import pedecode

def is_ca_cert(cert):
    try:
        bc = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
    except x509.extensions.ExtensionNotFound:
        bc = False
    if bc:
        return bc.value.ca
    return False

def print_cert(cert, ii, verbose = False):
    print(f'# {ii}   certificate')
    if verbose:
        print(f'# {ii}      subject: {cert.subject.rfc4514_string()}')
        print(f'# {ii}      issuer : {cert.issuer.rfc4514_string()}')
        print(f'# {ii}      valid  : {cert.not_valid_before} -> {cert.not_valid_after}')
        print(f'# {ii}      CA     : {is_ca_cert(cert)}')
    else:
        scn = pesign.cert_common_name(cert.subject)
        icn = pesign.cert_common_name(cert.issuer)
        print(f'# {ii}      subject CN: {scn}')
        print(f'# {ii}      issuer  CN: {icn}')

def print_vendor_cert(db, ii, verbose = False):
    sigdb = pedecode.vendor_cert_sigdb(db)
    for sl in sigdb:
        if str(sl.guid) == guids.EfiCertX509:
            print_cert(sl.x509, ii, verbose)
        elif str(sl.guid) == guids.EfiCertSha256:
            print(f'# {ii}   sha256')
            print(f'# {ii}      {len(sl)} entries')
        else:
            print(f'# {ii}   {sl.guid}')

def print_sbat_entries(ii, name, data):
    print(f'# {ii}{name}')
    entries = data.decode().rstrip('\n').split('\n')
    for entry in entries:
        print(f'# {ii}   {entry}')

def sig_type2(data, ii, extract = False, verbose = False, varlist = None):
    certs = pkcs7.load_der_pkcs7_certificates(data)
    for cert in certs:
        print_cert(cert, ii, verbose)
        if varlist:
            for var in ('db', 'dbx', 'MokListRT', 'MokListXRT'):
                if pesign.is_cert_in_sigdb(cert, varlist.get(var)):
                    print(f'# {ii}      certificate found in \'{var}\'')
                elif pesign.is_cert_issuer_in_sigdb(cert, varlist.get(var)):
                    print(f'# {ii}      cert issuer found in \'{var}\'')

        if extract:
            scn = pesign.cert_common_name(cert.subject)
            fn = "".join(x for x in scn if x.isalnum()) + '.pem'
            print(f'# {ii}      >>> {fn}')
            with open(fn, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

def pe_section_flags(sec):
    r = '-'
    w = '-'
    x = '-'
    if sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']:
        r = 'r'
    if sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']:
        w = 'w'
    if sec.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']:
        x = 'x'
    return r + w + x

# pylint: disable=too-many-arguments
def pe_print_sigs(filename, pe, indent, extract, verbose, varlist = None):
    i  = f'{"":{indent}s}'
    ii = f'{"":{indent+3}s}'
    sighdr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if sighdr.VirtualAddress and sighdr.Size:
        print(f'# {i}sigdata:'
              f' addr 0x{sighdr.VirtualAddress:08x} +0x{sighdr.Size:08x}')
        sigs = pe.__data__[ sighdr.VirtualAddress :
                            sighdr.VirtualAddress + sighdr.Size ]
        pos = 0
        index = 0
        while pos + 8 < len(sigs):
            (slen, srev, stype) = struct.unpack_from('<LHH', sigs, pos)
            print(f'# {ii}signature: len 0x{slen:x}, type 0x{stype:x}')
            if extract:
                index += 1
                fn = filename.split('/')[-1] + f'.sig{index}'
                print(f'# {ii}>>> {fn}')
                with open(fn, 'wb') as f:
                    f.write(sigs [ pos : pos + slen ])
            if stype == 2:
                sig_type2(sigs [ pos + 8 : pos + slen ],
                          ii, extract, verbose, varlist)
            pos += slen
            pos = (pos + 7) & ~7 # align

def pe_print_header(pe, indent):
    i = f'{"":{indent}s}'
    isize = pe.OPTIONAL_HEADER.SizeOfImage
    hsize = pe.OPTIONAL_HEADER.SizeOfHeaders
    dll   = pe.OPTIONAL_HEADER.DllCharacteristics
    nx    = "yes" if dll & 0x100 else "no"
    print(f'# {i}header: size=0x{hsize:x} imagesize=0x{isize:x} nx-compat={nx}')

def zboot_binary(pe, indent, verbose, varlist = None):
    i = f'{"":{indent}s}'
    (mz, zimg, zoff, zsize, r1, r2, alg) = struct.unpack_from('<I4sIIII8s', pe.get_data())
    if zimg != b'zimg':
        return

    zalg = pedecode.getcstr(alg).decode()
    print(f'# {i}zboot: 0x{zoff:x} +0x{zsize:x} ({zalg})')

    zdata = pe.__data__[ zoff : zoff + zsize ]
    if zalg == 'gzip':
        data = gzip.decompress(zdata)
    else:
        return

    print(f'# {i}   embedded binary')
    try:
        npe = pefile.PE(data = data)
        pe_print_header(npe, indent + 6)
        for nsec in npe.sections:
            pe_print_section(npe, nsec, indent + 6, verbose, varlist)
        pe_print_sigs(None, npe, indent + 6, False, verbose, varlist)
    except pefile.PEFormatError:
        print(f'# {i}      not a PE binary')

# pylint: disable=too-many-branches
def pe_print_section(pe, sec, indent, verbose, varlist = None):
    i  = f'{"":{indent}s}'
    ii = f'{"":{indent+3}s}'
    secname = pedecode.pe_section_name(pe, sec)
    print(f'# {i}section:'
          f' file 0x{sec.PointerToRawData:08x} +0x{sec.SizeOfRawData:08x}'
          f'  virt 0x{sec.VirtualAddress:08x} +0x{sec.Misc_VirtualSize:08x}'
          f'  {pe_section_flags(sec)} ({secname.decode()})')
    if secname == b'.vendor_cert':
        (db, dbx) = pedecode.pe_vendor_cert(sec)
        if db:
            print(f'# {ii}db')
            print_vendor_cert(db, ii, verbose)
        if dbx:
            print(f'# {ii}dbx')
            print_vendor_cert(dbx, ii, verbose)
    if secname == b'.sbatlevel':
        levels = sec.get_data()
        (version, poff, loff) = struct.unpack_from('<III', levels)
        print_sbat_entries(ii, 'previous', pedecode.getcstr(levels[poff + 4:]))
        print_sbat_entries(ii, 'latest', pedecode.getcstr(levels[loff + 4:]))
    if secname in (b'.sdmagic', b'.data.ident', b'.cmdline',
                    b'.uname', b'.sbat'):
        lines = sec.get_data().decode().rstrip('\n\0')
        for line in lines.split('\n'):
            print(f'# {ii}{line}')
    if secname == b'.osrel':
        osrel = sec.get_data().decode().rstrip('\n\0')
        entries = osrel.split('\n')
        for entry in entries:
            if entry.startswith('PRETTY_NAME'):
                print(f'# {ii}{entry}')
    if secname == b'.linux':
        print(f'# {ii}embedded binary')
        try:
            npe = pefile.PE(data = sec.get_data())
            pe_print_header(npe, indent + 6)
            for nsec in npe.sections:
                pe_print_section(npe, nsec, indent + 6, verbose, varlist)
            zboot_binary(npe, indent + 6, verbose, varlist)
            pe_print_sigs(None, npe, indent + 6, False, verbose, varlist)
        except pefile.PEFormatError:
            print(f'# {ii}   not a PE binary')

def efi_binary(filename, extract = False, verbose = False, varlist = None):
    print(f'# file: {filename}')
    try:
        pe = pefile.PE(filename)
        pe_print_header(pe, 3)
        for sec in pe.sections:
            pe_print_section(pe, sec, 3, verbose)
        zboot_binary(pe, 3, verbose)
        pe_print_sigs(filename, pe, 3, extract, verbose, varlist)
    except pefile.PEFormatError:
        print('#    not a PE binary')

def read_sig(filename):
    print(f'# <<< {filename} (signature)')
    with open(filename, 'rb') as f:
        blob = f.read()
    while len(blob) & 7:
        blob += b'\0'
    return blob

def efi_addsig(infile, outfile, sigfiles, replace = False):
    print(f'# <<< {infile} (efi binary)')
    pe = pefile.PE(infile)
    sighdr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    addr = sighdr.VirtualAddress
    size = sighdr.Size

    if addr:
        print(f'#    addr: 0x{addr:06x} +0x{size:06x} (existing sigs)')
        copy = addr + size
    else:
        addr = len(pe.__data__)
        copy = addr
        soze = 0
        print(f'#    addr: 0x{addr:06x} (no sigs, appending)')

    if size and replace:
        print('#    drop existing sigs')
        copy = addr
        size = 0

    addsigs = b''
    if sigfiles:
        for sigfile in sigfiles:
            blob = read_sig(sigfile)
            print(f'#    add sig (+0x{len(blob):06x})')
            addsigs += blob
            size += len(blob)

    if outfile:
        print(f'# >>> {outfile} (efi binary)')
        with open(outfile, 'wb') as f:
            print(f'#    fixup addr: 0x{addr:06x} +0x{size:06x} ')
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = addr
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = size
            print(f'#    copy: 0x{copy:06x} bytes')
            f.write(pe.write()[ : copy ])
            if len(addsigs):
                print(f'#    addsigs: 0x{len(addsigs):06x} bytes')
                f.write(addsigs)

def pe_dumpinfo():
    parser = argparse.ArgumentParser()
    parser.add_argument("FILES", nargs='*',
                        help="List of PE files to dump")
    options = parser.parse_args()
    for filename in options.FILES:
        print(f'# file: {filename}')
        pe = pefile.PE(filename)
        print(pe.dump_info())
    return 0

def pe_listsigs():
    parser = argparse.ArgumentParser(
        description = 'Print informations about PE/EFI binaries.')

    parser.add_argument('-x', '--extract', dest = 'extract',
                        action = 'store_true', default = False,
                        help = 'also extract signatures and certificates')
    parser.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print more certificate details')
    if pesign.cryptography_major >= 40:
        parser.add_argument('--findcert', '--find-cert', dest = 'findcert',
                            action = 'store_true', default = False,
                            help = 'check EFI databases for certs')
    parser.add_argument("FILES", nargs='*',
                        help="List of PE files to dump")
    options = parser.parse_args()

    varlist = None
    if pesign.cryptography_major >= 40 and options.findcert:
        varlist = linux.LinuxVarStore().get_varlist(volatile = True)

    for filename in options.FILES:
        efi_binary(filename, options.extract, options.verbose, varlist)
    return 0

def pe_addsigs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', dest = 'infile', type = str,
                        help = 'read efi binary from FILE', metavar = 'FILE')
    parser.add_argument('-o', '--output', dest = 'outfile', type = str,
                        help = 'write efi binary to FILE', metavar = 'FILE')
    parser.add_argument('-s', '--addsig', dest = 'addsigs',
                        type = str, action = 'append',
                        help = 'append  detached signature from FILE',
                        metavar = 'FILE')
    parser.add_argument('--replace', dest = 'replace',
                        action = 'store_true', default = False,
                        help = 'replace existing signatures')
    options = parser.parse_args()

    if not options.infile:
        print('missing input file (try --help)')
        return 1

    efi_addsig(options.infile, options.outfile, options.addsigs, options.replace)
    return 0

if __name__ == '__main__':
    sys.exit(pe_listsigs())
