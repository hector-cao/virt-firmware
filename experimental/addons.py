#!/usr/bin/python3
# pylint: disable=too-many-instance-attributes,consider-iterating-dictionary
""" handle UKI addons -- EXPERIMENTAL """
import os
import sys
import logging
import shutil
import argparse
import hashlib
import subprocess

from virt.firmware.efi import ucs16

from virt.firmware.bootcfg import bootcfg
from virt.firmware.bootcfg import linuxcfg

ESP_PATH = linuxcfg.LinuxOsInfo().esp_path()
DEFAULT_RPM_LOCATION = '/usr/lib/kernel/addons/'
GLOBAL_ADDONS_LOCATION = ESP_PATH + '/loader/addons/'
UKIFY_PATH = '/usr/lib/systemd/ukify'


def get_devpath(optdata):
    if optdata:
        if optdata and len(optdata) >= 4 and optdata[0] != 0 and optdata[1] == 0:
            path = ucs16.from_ucs16(optdata, 0)
            if path:
                return ESP_PATH + str(path).replace('\\', '/') + '.extra.d/'
    return None


def check_input_addon_exist(addon):
    """
    Check if the addon is an actual addon and exists (both in the given location or in
    DEFAULT_RPM_LOCATION).
    Returns the full path to the addon.
    """
    if not addon.endswith('.addon.efi'):
        logging.error('addon must end with .addon.efi')
        sys.exit(1)
    if not os.path.exists(addon):
        old_addon = addon
        addon = DEFAULT_RPM_LOCATION + addon
        if not os.path.exists(addon):
            logging.error('addon %s does not exist, not even in %s', old_addon, addon)
            sys.exit(1)
    return addon


def check_global_addon_exist(fail=True):
    """
    Check if GLOBAL_ADDONS_LOCATION exist
    """
    if os.path.exists(GLOBAL_ADDONS_LOCATION):
        return True
    if fail:
        logging.error('Global addons location %s does not exist', GLOBAL_ADDONS_LOCATION)
        sys.exit(1)
    return False


def check_global_addon_option(options, fail=True):
    """
    Checks if --global is not given together with --uki-path or --uki-title.
    Returns GLOBAL_ADDONS_LOCATION
    """
    if options.uki_title or options.uki_path:
        if fail:
            logging.error('destination for the addon is either global addons or specific uki')
            sys.exit(1)
        return False
    return GLOBAL_ADDONS_LOCATION


def check_title_option(cfg, options):
    """
    Given a title, finds its entry in cfg and returns the path to the UKI
    """
    if options.uki_path:
        logging.error('cannot specify --title and --dest-uki together')
        sys.exit(1)
    nr = cfg.find_title_entry(options.uki_title)
    if nr is None:
        logging.error('boot entry %s does not exist', options.uki_title)
        sys.exit(1)
    entry = cfg.get_entry(nr)
    if entry is None:
        logging.error('boot entry %s does not exist', options.uki_title)
        sys.exit(1)
    path = get_devpath(entry.optdata)
    if path:
        return path
    logging.error('boot entry %s does not contain a device path', options.uki_title)
    sys.exit(1)


def check_path_option(uki):
    """
    Checks that the given UKI path (or extra.d path) exists.
    Returns the path to the .extra.d folder, but does not check if that actually exists
    """
    if not os.path.exists(uki):
        logging.error('File/folder %s not found', uki)
        sys.exit(1)
    # .efi file, append .extra.d/ and return
    if uki.endswith('.efi'):
        return uki + '.extra.d/'
    # either .extra.d or something else, append '/' if missing
    if not uki.endswith('/'):
        uki += '/'
    # must be .extra.d/, otherwise fail
    if not uki.endswith('.extra.d/'):
        logging.error('%s is not a UKI', uki)
        sys.exit(1)
    return uki


def install_uki_addon(cfg, options):
    """
    cp options.install_addon in a specific destination
    *) with no param, fail
    *) with --global, cp in GLOBAL_ADDONS_LOCATION
    *) with --uki-path/uki-title, cp in
       /boot/efi/EFI/Linux/uki_name.efi.extra.d/options.install_addon
    """
    options.install_addon = check_input_addon_exist(options.install_addon)

    destination = None
    if options.global_addon:
        destination = check_global_addon_option(options)
        if not os.path.exists(ESP_PATH):
            logging.error("%s does not exist", ESP_PATH)
            sys.exit(1)
    elif options.uki_title:
        destination = check_title_option(cfg, options)
    elif options.uki_path:
        destination = check_path_option(options.uki_path)
    else:
        logging.error('please specify a target uki with --title/--dest-uki or --global-addons')
        sys.exit(1)

    os.makedirs(destination, exist_ok=True)
    logging.info('Folder where the addon will be installed: %s', destination)
    new_addon_path = destination + os.path.basename(options.install_addon)
    if os.path.exists(new_addon_path):
        logging.error('addon %s exists already', new_addon_path)
        sys.exit(1)

    shutil.copy(options.install_addon, destination)
    logging.info('Installed addon %s to %s', options.install_addon, destination)


def rm_addon(path, fail=True):
    if os.path.exists(path):
        os.remove(path)
        return True
    if fail:
        logging.error('addon %s does not exist', path)
        sys.exit(1)
    return False


def rm_uki_addon(cfg, options):
    """
    rm options.rm_addon
    *) with no param, just behave like `rm`. If not found, search also in DEFAULT_RPM_LOCATION.
    *) with --global, rm GLOBAL_ADDONS_LOCATION/options.rm_addon
    *) with --uki-path/uki-title, rm /boot/efi/EFI/Linux/uki_name.efi.extra.d/options.rm_addon
    """
    if options.global_addon:
        check_global_addon_exist()
        destination = check_global_addon_option(options) + options.rm_addon
    elif options.uki_title:
        destination = check_title_option(cfg, options) + options.rm_addon
    elif options.uki_path:
        destination = check_path_option(options.uki_path) + options.rm_addon
    else:
        destination = check_input_addon_exist(options.rm_addon)

    rm_addon(destination)
    logging.info('Removed addon %s', destination)


def get_file_sha(path):
    sha256 = hashlib.sha256()

    with open(path, 'rb') as f:
        BUF_SIZE = 65536
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()


def update_installed_addon(path, options, fail=True):
    if not os.path.exists(path):
        if fail:
            logging.error('%s does not exist', path)
            sys.exit(1)
        return False

    addon = os.path.basename(options.update_addon)
    installed_addon_path = path + addon
    if not os.path.exists(installed_addon_path):
        if fail:
            logging.error('addon %s does not exist', installed_addon_path)
            sys.exit(1)
        return False
    logging.debug('Found addon %s', installed_addon_path)

    old_addon_sha = get_file_sha(installed_addon_path)
    new_addon_sha = get_file_sha(options.update_addon)
    if old_addon_sha != new_addon_sha:
        shutil.copy(options.update_addon, installed_addon_path)
        logging.info('Updated addon %s to %s', options.update_addon, installed_addon_path)
    else:
        logging.info("Addon %s unchanged", installed_addon_path)
    return True


def update_uki_addon(cfg, options):
    """
    cp options.update_addon replacing another one already installed.
    Replacement is only done if name matches and sha256 differs.
    *) with no param, update all *installed* UKIs and GLOBAL_ADDONS_LOCATION if
       there is an addon matching. Replace *all* matching
    *) with --global, just update the one in GLOBAL_ADDONS_LOCATION
    *) with --uki-path/uki-title, update the one in
       /boot/efi/EFI/Linux/uki_name.efi.extra.d/options.update_addon
    """
    options.update_addon = check_input_addon_exist(options.update_addon)

    destination = None
    if options.global_addon:
        destination = check_global_addon_option(options)
        check_global_addon_exist()
        update_installed_addon(destination, options)
    elif options.uki_title:
        destination = check_title_option(cfg, options)
        update_installed_addon(destination, options)
    elif options.uki_path:
        destination = check_path_option(options.uki_path)
        update_installed_addon(destination, options)
    else:
        # update all UKIs
        installed_addon = False
        if check_global_addon_exist(fail=False):
            installed_addon = update_installed_addon(GLOBAL_ADDONS_LOCATION, options, fail=False)
        for entry in cfg.bentr.values():
            destination = get_devpath(entry.optdata)
            if destination:
                installed_addon |= update_installed_addon(destination, options, fail=False)
        if not installed_addon:
            logging.error('no addon found to update in global addons folder or installed ukis')
            sys.exit(1)


def print_addons_folder(path, options):
    found = 0
    for addon in os.listdir(path):
        if not addon.endswith('.addon.efi'):
            continue
        fullpath = path + addon
        print(f'  {fullpath}')
        found += 1
        if options.verbose:
            cmd = f'{UKIFY_PATH} inspect {fullpath}'.split()
            out = subprocess.check_output(cmd, text=True)
            out = '    ' + out.replace('\n', '\n    ')
            print(out, end=None)
    return found


def show_all_addons(destination, options, global_addons=True):
    print('#' * len(destination))
    print(destination)
    print('#' * len(destination))

    found = 0
    if global_addons and check_global_addon_exist(fail=False):
        found += print_addons_folder(GLOBAL_ADDONS_LOCATION, options)
    found += print_addons_folder(destination, options)
    if found == 0:
        print('    No UKI addons found\n\n')
    elif not options.verbose:
        print()


def list_addons_path(options):
    """
    list all addons in a folder
    *) with no params, look into DEFAULT_RPM_LOCATION
    *) with --verbose, print all addon sections
    """
    #options.list_addons is False if undefined, is True if defined without
    # folder and a string if the folder is provided
    destination = options.list_addons
    if options.list_addons is True:
        # no option provided, look in DEFAULT_RPM_LOCATION
        destination = DEFAULT_RPM_LOCATION
    show_all_addons(destination, options, global_addons=False)


def show_installed_addons(cfg, options):
    """
    list all addons installed
    *) with no params, lisft all addons in GLOBAL_ADDONS_LOCATION and all *installed* UKIs.
    *) with --global, show only the global addons. If GLOBAL_ADDONS_LOCATION does not exist, fail
    *) with --uki-path/uki-title, show all addons used by a specific UKI
    *) with --verbose, print all addon sections
    """
    destination = None
    if options.global_addon:
        destination = check_global_addon_option(options, fail=options.global_addon)
        check_global_addon_exist()
    elif options.uki_title:
        destination = check_title_option(cfg, options)
    elif options.uki_path:
        destination = check_path_option(options.uki_path)

    if destination:
        show_all_addons(destination, options, global_addons=options.global_addon is None)
    else:
        for entry in cfg.bentr.values():
            path = get_devpath(entry.optdata)
            if path:
                show_all_addons(path, options)


# pylint: disable=too-many-boolean-expressions,too-many-branches,too-many-statements
def main():
    parser = argparse.ArgumentParser(
        description = 'show and manage UKI addons')

    parser.add_argument('-l', '--loglevel', dest = 'loglevel', type = str, default = 'info',
                        help = 'set loglevel to LEVEL', metavar = 'LEVEL')
    parser.add_argument('--vars', dest = 'varsfile', type = str,
                        help = 'read edk2 vars from FILE', metavar = 'FILE')
    parser.add_argument('-v', '--verbose', dest = 'verbose',
                        action = 'store_true', default = False,
                        help = 'print more details')

    group = parser.add_argument_group('update unified kernel image (UKI) addons')
    group.add_argument('--install-addon', dest = 'install_addon', type = str,
                       help = 'install addon FILE', metavar = 'FILE')
    group.add_argument('--update-addon', dest = 'update_addon', type = str,
                       help = 'update addon FILE', metavar = 'FILE')
    group.add_argument('--remove-addon', dest = 'rm_addon', type = str,
                       help = 'remove addon FILE', metavar = 'FILE')
    group.add_argument('--list-addons', dest = 'list_addons', type = str, nargs='?',
                       const = True, help = 'list all addons in PATH', metavar = 'PATH')
    parser.add_argument('--show-installed', dest = 'show',
                        action = 'store_true', default = False,
                        help = 'list all installed addons')

    group = parser.add_argument_group('options for UKI addons updates')
    group.add_argument('--global', dest = 'global_addon',
                       action = 'store_true', default = False,
                       help = f'work only with addons in  {GLOBAL_ADDONS_LOCATION}')
    group.add_argument('--uki-title', dest = 'uki_title', type = str,
                       help = 'work only with addons in UKI labelled TITLE',
                       metavar = 'TITLE')
    group.add_argument('--uki-path', dest = 'uki_path', type = str,
                       help = 'work only with addons used by the UKI in PATH',
                       metavar = 'PATH')

    options = parser.parse_args()

    logging.basicConfig(format = '%(levelname)s: %(message)s',
                        level = getattr(logging, options.loglevel.upper()))

    # read info
    if options.varsfile:
        cfg = bootcfg.VarStoreEfiBootConfig(options.varsfile)
    else:
        cfg = linuxcfg.LinuxEfiBootConfig()

    # apply updates
    if options.install_addon:
        install_uki_addon(cfg, options)
    elif options.rm_addon:
        rm_uki_addon(cfg, options)
    elif options.update_addon:
        update_uki_addon(cfg, options)
    elif options.list_addons:
        list_addons_path(options)
    else:
        show_installed_addons(cfg, options)

    return 0

if __name__ == '__main__':
    sys.exit(main())
