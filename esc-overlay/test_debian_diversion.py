"""Real dpkg package upgrade in a disposable root; no host package/service writes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DebianPackageControl(unittest.TestCase):
    def run_command(self, *args):
        return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()

    def package(self, directory, version, argument):
        source = directory / ('package-' + version)
        (source / 'DEBIAN').mkdir(parents=True)
        (source / 'DEBIAN/control').write_text(
            'Package: esc-lldap-overlay-fixture\nVersion: ' + version +
            '\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: isolated control\n')
        binary = source / 'usr/bin/lldap'
        binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\nprintf "VENDOR-' + version + ':%s\\n" "$*"\n')
        binary.chmod(0o755)
        unit = source / 'usr/lib/systemd/system/lldap.service'
        unit.parent.mkdir(parents=True)
        unit.write_text('[Service]\nExecStart=/usr/bin/lldap run --config-file ' + argument + '\n')
        unit.chmod(0o644)
        output = directory / ('fixture-' + version + '.deb')
        self.run_command('/usr/bin/dpkg-deb', '--root-owner-group', '--build', str(source), str(output))
        return output

    def test_current_package_update_and_changed_unit_arguments_survive_owned_rollback(self):
        runtime = load('divert_runtime')
        activation = load('activate')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            root = directory / 'root'
            (root / 'var/lib/dpkg/updates').mkdir(parents=True)
            (root / 'var/lib/dpkg/status').touch()
            root.chmod(0o700)
            first = self.package(directory, '1', '/old/config.toml')
            second = self.package(directory, '2', '/new/package-config.toml')
            for path in root.rglob('*'):
                if path.is_dir():
                    path.chmod(0o755)
            install = ['/usr/bin/dpkg', '--root=' + str(root), '--force-not-root', '--force-bad-path', '--unpack']
            self.run_command(*install, str(first))
            package = root / 'usr/bin/lldap'
            vendor = root / 'usr/lib/lldap-esc/lldap.distrib'
            vendor.parent.mkdir(mode=0o755)
            vendor.parent.chmod(0o755)
            diversion = ['/usr/bin/dpkg-divert', '--root=' + str(root), '--local',
                         '--divert', '/usr/lib/lldap-esc/lldap.distrib', '--rename']
            self.run_command(*diversion, '--add', '/usr/bin/lldap')
            self.assertEqual(self.run_command('/usr/bin/dpkg-divert', '--root=' + str(root),
                                              '--listpackage', '/usr/bin/lldap'), 'LOCAL')
            release = root / 'release'
            release.mkdir(mode=0o755)
            release.chmod(0o755)
            candidate = release / 'lldap'
            candidate.write_text('#!/bin/sh\nprintf "CANDIDATE:%s\\n" "$*"\n')
            candidate.chmod(0o555)
            unit = root / 'usr/lib/systemd/system/lldap.service'
            config = {'format': 'lldap-esc-overlay-v1', 'baseline_package_version': '1',
                      'baseline_sha256': hashlib.sha256(vendor.read_bytes()).hexdigest(),
                      'artifact_sha256': hashlib.sha256(candidate.read_bytes()).hexdigest(),
                      'baseline_unit_sha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
                      'baseline_dropins': {}}
            (release / 'deployment.json').write_text(json.dumps(config))
            (release / 'deployment.json').chmod(0o444)
            options = {'owner_uid': os.getuid(), 'trust_root': root, 'vendor_unit': unit, 'dropin_dirs': ()}
            for path in root.rglob('*'):
                if path.is_dir():
                    path.chmod(0o755)
            selected, status = runtime.select(release, vendor, '1', **options)
            self.assertEqual(selected, candidate)
            self.assertEqual(status['atomic_api'], 'PENDING_LIVE_PROOF')
            record = activation.create_owned(package, b'owned wrapper bytes', 0o555)
            self.run_command(*install, str(second))
            self.assertEqual(package.read_bytes(), b'owned wrapper bytes')
            new_arguments = unit.read_text().split('ExecStart=/usr/bin/lldap ', 1)[1].strip().split()
            selected, status = runtime.select(release, vendor, '2', **options)
            self.assertEqual(selected, vendor)
            self.assertEqual(status['atomic_api'], 'PENDING')
            output = self.run_command(str(selected), *runtime.forward_argv(new_arguments)[1:])
            self.assertEqual(output, 'VENDOR-2:run --config-file /new/package-config.toml')
            activation.remove_owned(package, record, os.getuid())
            self.run_command(*diversion, '--remove', '/usr/bin/lldap')
            self.assertFalse(vendor.exists())
            self.assertEqual(self.run_command(str(package), *new_arguments), output)
