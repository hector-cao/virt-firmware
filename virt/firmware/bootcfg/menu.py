#!/usr/bin/python3
#
# SPDX-License-Identifier: GPL-2.0-only
# (c) 2023 Gerd Hoffmann
#
""" efi boot menu """
import os
import sys
import argparse
import subprocess

from virt.firmware.bootcfg import linuxcfg

def bootmenu(cfg):
    rows = os.get_terminal_size().lines
    cols = os.get_terminal_size().columns
    cmdline = [ 'dialog', '--menu', 'uefi boot menu',
                str(rows - 10), str(cols - 30), str(rows - 18) ]

    for (nr, entry) in cfg.bentr.items():
        cmdline += [ str(nr), str(entry.title) ]

    result = subprocess.run(cmdline, stderr = subprocess.PIPE, check = False)
    subprocess.run(['clear',], check = True)
    if result.returncode != 0:
        return None
    return int(result.stderr.decode())

def main():
    parser = argparse.ArgumentParser(
        description = 'uefi boot menu')
    parser.add_argument('-r', '--reboot', dest = 'reboot',
                        default = False, action = 'store_true',
                        help = 'reboot after picking an entry')
    options = parser.parse_args()

    cfg = linuxcfg.LinuxEfiBootConfig()
    nr = bootmenu(cfg)
    if nr is None:
        return 0

    cfg.set_boot_next(nr)
    try:
        cfg.linux_update_next()
    except PermissionError:
        print('Can not update BootNext (try run as root)')
        return 1

    if options.reboot:
        message = f'reboot into {cfg.bentr[nr].title}'
        subprocess.run(['/usr/sbin/shutdown', '-r', 'now', message], check = True)

    return 0

if __name__ == '__main__':
    sys.exit(main())
