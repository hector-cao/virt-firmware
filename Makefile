
PYLINT_OPTS	:=
PYLINT_OPTS	+= --py-version 3.6	# matches setup.py declaration
PYLINT_OPTS	+= -d invalid-name	# using efi-style names in some places
PYLINT_OPTS	+= -d unused-variable	# happens often when unpacking structss
PYLINT_OPTS	+= -d too-many-locals	# happens when unpacking structss
PYLINT_OPTS	+= -d R0801		# duplicate-code (simliar cmd line opts)
PYLINT_OPTS	+= -d deprecated-module			# TODO
PYLINT_OPTS	+= -d missing-function-docstring	# TODO
PYLINT_OPTS	+= --extension-pkg-allow-list=crc32c

PKG_VERSION	:= $(shell awk '/version/ { print $$3 }' setup.cfg)
PKG_TARBALL	:= dist/virt_firmware-$(PKG_VERSION).tar.gz

MANPAGES	:= man/virt-fw-dump.1
MANPAGES	+= man/virt-fw-vars.1
MANPAGES	+= man/virt-fw-sigdb.1
MANPAGES	+= man/kernel-bootcfg.1
MANPAGES	+= man/uefi-boot-menu.1
MANPAGES	+= man/pe-inspect.1

default:
	@echo "targets: lint install uninstall clean"

lint pylint:
	pylint $(PYLINT_OPTS) virt/firmware virt/peutils experimental

.PHONY: dist
dist tarball $(PKG_TARBALL):
	rm -rf dist
	python3 -m build
	twine check dist/*

rpm rpms package: $(PKG_TARBALL)
	rm -rf rpms
	mkdir -p rpms/src
	pyp2rpm -d rpms/src --srpm $(PKG_TARBALL)
	rpmbuild --rebuild \
		--define "_rpmdir rpms" \
		--define "_srcrpmdir rpms/src" \
		rpms/src/*.src.rpm
	createrepo rpms


man manpages: $(MANPAGES)

man/%.1:
	help2man --version-string $(PKG_VERSION) --no-info --include man/$*.inc $* > $@

man/virt-fw-dump.1:  setup.cfg virt/firmware/dump.py man/virt-fw-dump.inc
man/virt-fw-vars.1:  setup.cfg virt/firmware/vars.py man/virt-fw-vars.inc
man/virt-fw-sigdb.1: setup.cfg virt/firmware/sigdb.py man/virt-fw-sigdb.inc
man/kernel-bootcfg.1: setup.cfg virt/firmware/sigdb.py man/kernel-bootcfg.inc
man/uefi-boot-menu.1: setup.cfg virt/firmware/sigdb.py man/uefi-boot-menu.inc
man/pe-inspect.1: setup.cfg virt/peutils/peutils.py man/pe-inspect.inc


install:
	python3 -m pip install --user .

uninstall:
	python3 -m pip uninstall virt-firmware

test check: test-dump test-vars test-sigdb test-pe test-bootcfg test-unittest

test-dump:
	tests/test-dump.sh

test-vars:
	tests/test-vars.sh

test-pe:
	tests/test-pe.sh

test-bootcfg:
	tests/test-bootcfg.sh

test-sigdb:
	tests/test-sigdb.sh

test-unittest:
	python3 tests/tests.py

clean:
	rm -rf build virt_firmware.egg-info $(PKG_TARBALL) rpms dist
	rm -rf *~ virt/firmware/*~ virt/firmware/efi/*~
	rm -rf *~ virt/firmware/__pycache__ virt/firmware/efi/__pycache__
