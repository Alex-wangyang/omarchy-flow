"""Exercise release CLI with committed files and independently repacked archives."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('release.py')
COMPONENT = Path('src')
VERSION = 'v0.1.0-rc.1'


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.bundle = self.root / 'bundle'
        self.stage = self.root / 'stage'
        self.archive = self.bundle / 'omarchy-flow.tar.gz'
        for name in ('src', 'tests', 'packaging'):
            shutil.copytree(SCRIPT.parents[1] / name, self.root / name,
                            ignore=shutil.ignore_patterns('aur', '__pycache__', '*.pyc'))
        for name in ('LICENSE', 'README.md', 'README.zh-CN.md', 'PROTOCOL.md', 'requirements.lock'):
            shutil.copyfile(SCRIPT.parents[1] / name, self.root / name)
        for args in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Test', '-c', 'user.email=test@example.org',
                      '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture']):
            subprocess.run(['git', *args], cwd=self.root, check=True)
        self.commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        self.cli('build')

    def cli(self, op, *extra, ok=True, version=VERSION, commit=None):
        args = [sys.executable, '-B', SCRIPT, op]
        if op != 'render-units':
            args += ['--bundle', self.bundle, '--commit', commit or self.commit, '--version', version]
        result = subprocess.run(args + list(extra), cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)

    def test_version_syntax(self):
        for version in ('v01.2.3', 'v1.02.3', 'v1.2.03', 'v1.2.3-rc..1',
                        'v1.2.3-01', 'v1.2.3-rc.01', 'v1.2.3-', 'v1.2.3-rc.',
                        'v1.2.3+', 'v1.2.3+build..1', 'v1.2.3+build.', 'v1.2.3+build_1'):
            with self.subTest(version=version):
                shutil.rmtree(self.bundle, ignore_errors=True)
                self.cli('build', version=version, ok=False)
        for version in ('v0.1.0', 'v1.2.3-rc.1', 'v1.2.3-alpha.0',
                        'v1.2.3+build.7', 'v1.2.3+001', 'v1.2.3+build-1', 'v1.2.3-rc.1+build.7'):
            with self.subTest(version=version):
                shutil.rmtree(self.bundle, ignore_errors=True)
                self.cli('build', version=version)

    def test_build_metadata_stage_and_render(self):
        version = 'v1.2.3+build.7'
        shutil.rmtree(self.bundle, ignore_errors=True)
        self.cli('build', version=version)
        self.cli('verify', version=version)
        stage = self.root / (version + '.test')
        self.cli('stage', '--target', stage, version=version)
        units = self.root / 'units-build'
        self.cli('render-units', '--stage', stage, '--python', sys.executable, '--out', units)
        folder = units / 'omarchy-plugin' / 'io.github.alexwangyang.omarchy-flow'
        manifest = json.loads((folder / 'manifest.json').read_bytes())
        self.assertEqual(manifest['version'], '1.2.3+build.7')
        self.assertEqual(manifest['entryPoints']['barWidget'], 'v1.2.3+build.7/FlowWidget.qml')
        self.assertTrue((folder / 'v1.2.3+build.7' / 'FlowWidget.qml').is_file())

    def test_lifecycle(self):
        self.cli('verify')
        self.cli('stage', '--target', self.stage)
        self.cli('stage', '--target', self.stage, ok=False)
        receipt = json.loads((self.stage / 'STAGE_RECEIPT.json').read_text())
        self.assertEqual(receipt, dict(file_count=35, source_commit=self.commit, version=VERSION,
                                       archive_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest()))
        self.assertEqual((self.stage / COMPONENT / 'flow_ui.py').stat().st_mode & 0o777, 0o755)
        units = self.root / 'units'
        self.cli('render-units', '--stage', self.stage, '--python', sys.executable, '--out', units)
        for name in ('omarchy-flow.service', 'omarchy-flow.desktop'):
            data = (units / name).read_text()
            self.assertIn(str(self.stage / COMPONENT), data)
            self.assertNotIn('@FLOW_DIR@', data)
            self.assertNotIn('@PYTHON_BIN@', data)

        folder = units / 'omarchy-plugin' / 'io.github.alexwangyang.omarchy-flow'
        manifest = json.loads((folder / 'manifest.json').read_bytes())
        self.assertEqual((units / '70-omarchy-flow.rules').read_bytes(),
                         (self.stage / 'packaging/70-omarchy-flow.rules').read_bytes())
        self.assertEqual(manifest['id'], folder.name)
        self.assertEqual(manifest['kinds'], ['bar-widget'])
        qml = (folder / manifest['entryPoints']['barWidget']).read_text()
        flow = self.stage / COMPONENT
        for name in ('flow_bar.py', 'flow_i18n.py'):
            self.assertTrue((flow / name).is_file(), name)
        self.assertIn(json.dumps(str(flow / 'flow_bar.py')), qml)
        self.assertIn(json.dumps('exec ' + str(flow / 'flow_ui.py')), qml)
        self.assertNotIn('@BAR_HELPER@', qml)
        self.assertNotIn('@OPEN_SETTINGS@', qml)
        self.assertEqual(manifest['entryPoints']['barWidget'], VERSION + '/FlowWidget.qml')
        self.assertEqual(manifest['version'], VERSION.removeprefix('v'))
        self.cli('render-units', '--stage', self.stage, '--python', sys.executable, '--out', units, ok=False)

    def test_render_rejects_shell_metacharacters(self):
        self.cli('stage', '--target', self.stage)
        self.cli('render-units', '--stage', self.stage, '--python', sys.executable,
                 '--out', self.root / 'unsafe$path', ok=False)

    def test_damaged_plugin_stage_rejected_before_render(self):
        self.cli('stage', '--target', self.stage)
        receipt = self.stage / 'STAGE_RECEIPT.json'
        receipt.write_text(json.dumps({'version': '../other'}))
        units = self.root / 'units'
        self.cli('render-units', '--stage', self.stage, '--python', sys.executable, '--out', units, ok=False)
        self.assertFalse(units.exists())
        receipt.write_text(json.dumps({'version': VERSION}))
        (self.stage / COMPONENT / 'flow_bar.py').unlink()
        self.cli('render-units', '--stage', self.stage, '--python', sys.executable, '--out', units, ok=False)
        self.assertFalse(units.exists())

    def test_identity_checksums_and_ancestor(self):
        self.cli('verify', version='v0.1.0-rc.2', ok=False)
        self.cli('verify', commit='1' * 40, ok=False)
        alias = self.root / 'alias'
        alias.symlink_to(self.root)
        self.cli('stage', '--target', alias / 'stage', ok=False)
        self.assertFalse(self.stage.exists())
        (self.bundle / 'SHA256SUMS').write_text('')
        self.cli('verify', ok=False)

    def test_invalid_members(self):
        original = self.archive.read_bytes()
        for change in ('extra', 'missing', 'symlink', 'traversal', 'duplicate', 'bad-content'):
            with self.subTest(change=change):
                with tarfile.open(fileobj=io.BytesIO(original), mode='r:gz') as src, \
                        tarfile.open(self.archive, 'w:gz') as dest:
                    for m in src:
                        if m.name == 'README.md':
                            if change == 'missing':
                                continue
                            if change == 'duplicate':
                                dest.addfile(m, src.extractfile(m))
                            if change == 'symlink':
                                m.type, m.linkname, m.size = tarfile.SYMTYPE, '/outside', 0
                            if change == 'traversal':
                                stream = src.extractfile(m)
                                m.name = '../outside'
                                dest.addfile(m, stream)
                                continue
                            if change == 'bad-content':
                                dest.addfile(m, io.BytesIO(b'x' * m.size))
                                continue
                        dest.addfile(m, src.extractfile(m) if m.isfile() else None)
                    if change == 'extra':
                        dest.addfile(tarfile.TarInfo('extra'))
                names = [self.archive, self.bundle / 'release.json']
                (self.bundle / 'SHA256SUMS').write_text(''.join(
                    f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in names))
                self.cli('stage', '--target', self.stage, ok=False)
                self.assertFalse(self.stage.exists())
