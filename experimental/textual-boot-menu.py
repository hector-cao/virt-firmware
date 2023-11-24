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

from textual.app import App, ComposeResult, Binding
from textual.widgets import Header, Static, Label, Button, ListItem, ListView

from virt.firmware.bootcfg import linuxcfg

class BootMenuApp(App):

    CSS = """

    Header {
        height: 3;
    }
    
    #list ListItem {
        layout: horizontal;
    }

    #nr, #title {
        margin: 1 3;
    }

    #buttons {
        layout: horizontal;
        margin: 1;
    }

    #buttons Button {
        margin: 0 3;
    }

    """

    BINDINGS = [
        Binding('enter', 'hotkey("#ok")', 'OK', priority = True),
        Binding('escape', 'hotkey("#cancel")', 'Cancel'),
    ]

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg

    def compose(self) -> ComposeResult:
        yield Header()
        with ListView(id = 'list'):
            for (nr, entry) in self.cfg.bentr.items():
                yield ListItem(Label(str(nr), id = 'nr'),
                               Label(str(entry.title), id = 'title'),
                               id = f'boot{nr:04d}')
        with Static(id = 'buttons'):
            yield Button('OK', id = 'ok', variant = 'success')
            yield Button('Cancel', id = 'cancel', variant = 'error')

    def action_hotkey(self, name) -> None:
        btn = self.query_one(name)
        btn.press()

    def on_mount(self) -> None:
        self.title = "UEFI Boot Menu"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'cancel':
            self.exit(None)
            return

        item = self.query_one('#list').highlighted_child
        if item is None:
            self.exit(None)
            return

        boot = item.id.lstrip('boot')
        self.exit(int(boot))
        

def main():
    parser = argparse.ArgumentParser(
        description = 'uefi boot menu')
    parser.add_argument('-r', '--reboot', dest = 'reboot',
                        default = False, action = 'store_true',
                        help = 'reboot after picking an entry')
    options = parser.parse_args()

    cfg = linuxcfg.LinuxEfiBootConfig()
    app = BootMenuApp(cfg)
    nr = app.run()
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
