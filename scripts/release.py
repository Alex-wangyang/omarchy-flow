#!/usr/bin/env python3
"""Build, verify and stage versioned Omarchy Flow releases."""
import argparse
from contextlib import ExitStack, contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile

PLUGIN_ID = 'io.github.alexwangyang.omarchy-flow'
PLUGIN_SOURCE = Path('packaging/omarchy-plugin')
FILES = frozenset("""
    LICENSE README.md README.zh-CN.md PROTOCOL.md requirements.lock
    src/bolt_hidpp.py src/fars.py src/flow_bar.py src/flow_clipboard.py
    src/flow_clipboard_manager.py src/flow_control.py src/flow_daemon.py
    src/flow_i18n.py src/flow_probe.py src/flow_switcher.py src/flow_transfer.py
    src/flow_ui.py src/hyprland_edges.py src/marconi_crypto.py src/marconi_packets.py
    tests/test_bolt_hidpp.py tests/test_flow_bar.py tests/test_flow_clipboard.py
    tests/test_flow_control.py tests/test_flow_daemon.py tests/test_flow_i18n.py
    tests/test_flow_probe.py tests/test_flow_ui.py tests/test_hyprland_edges.py
    tests/test_marconi_protocol.py packaging/omarchy-flow.desktop.in
    packaging/omarchy-flow.service.in packaging/70-omarchy-flow.rules
    packaging/omarchy-plugin/manifest.json packaging/omarchy-plugin/FlowWidget.qml.in
""".split())
DIRECTORIES = sorted({parent for name in FILES for parent in Path(name).parents
                      if parent != Path('.')})
METADATA = {'schema': 'omarchy-flow-release-v2', 'repository': 'Alex-wangyang/omarchy-flow',
            'component': 'omarchy-flow', 'platform': 'linux-x86_64', 'runtime': 'Python 3.14',
            'dependencies_lock': 'requirements.lock'}
NUMBER = r'(?:0|[1-9][0-9]*)'
LABEL = rf'(?:{NUMBER}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
BUILD = r'[0-9A-Za-z-]+'
VERSION_PATTERN = rf'v{NUMBER}\.{NUMBER}\.{NUMBER}(?:-{LABEL}(?:\.{LABEL})*)?(?:\+{BUILD}(?:\.{BUILD})*)?'
ARCHIVE = 'omarchy-flow.tar.gz'
MANIFEST = 'release.json'
MAX_FILE = 1024 * 1024
MAX_ARCHIVE = MAX_FILE * (len(FILES) + 1)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checksums(archive, manifest):
    return f'{digest(archive)}  {ARCHIVE}\n{digest(manifest)}  {MANIFEST}\n'.encode()


def limited(stream, limit):
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('size limit exceeded')
    return data


def read(path, limit):
    with path.open('rb') as stream:
        return limited(stream, limit)


def build(bundle, commit, version):
    if subprocess.check_output(['git', 'cat-file', '-t', commit]).strip() != b'commit':
        raise ValueError('expected a commit object')
    tree = subprocess.check_output(['git', 'ls-tree', '-rz', commit]).decode()
    blobs = {}
    for entry in tree.rstrip('\0').split('\0'):
        header, name = entry.split('\t', 1)
        if name not in FILES:
            if name.startswith(('src/', 'tests/', 'packaging/')) and not name.startswith('packaging/aur/'):
                raise ValueError(f'unlisted component file: {name}')
            continue
        mode, kind, oid = header.split()
        if kind != 'blob' or mode != ('100755' if name == 'src/flow_ui.py' else '100644'):
            raise ValueError(f'unexpected source mode: {name}')
        blobs[name] = subprocess.check_output(['git', 'cat-file', 'blob', oid])
    if blobs.keys() != FILES:
        raise ValueError('committed component differs from release allowlist')
    hashes = {name: digest(data) for name, data in blobs.items()}
    bundle.mkdir(mode=0o700)
    # Stable archive bytes let distro recipes pin the payload independently of
    # packaging-only commits. The release manifest binds it to the reviewed SHA.
    with (bundle / ARCHIVE).open('xb') as output:
        with gzip.GzipFile(filename='', fileobj=output, mode='wb', compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                for name in sorted(blobs):
                    info = tarfile.TarInfo(name)
                    info.size = len(blobs[name])
                    info.mode = 0o755 if name == 'src/flow_ui.py' else 0o644
                    tar.addfile(info, io.BytesIO(blobs[name]))
    metadata = {**METADATA, 'source_commit': commit, 'version': version, 'files': hashes}
    manifest = (json.dumps(metadata, indent=2, sort_keys=True) + '\n').encode()
    (bundle / MANIFEST).write_bytes(manifest)
    (bundle / 'SHA256SUMS').write_bytes(checksums(read(bundle / ARCHIVE, MAX_ARCHIVE), manifest))


def verify(bundle, commit, version):
    archive = read(bundle / ARCHIVE, MAX_ARCHIVE)
    manifest = read(bundle / MANIFEST, MAX_FILE)
    if read(bundle / 'SHA256SUMS', 512) != checksums(archive, manifest):
        raise ValueError('release checksums differ')
    metadata = json.loads(manifest)
    hashes = metadata.pop('files')
    if metadata != {**METADATA, 'source_commit': commit, 'version': version} or set(hashes) != FILES:
        raise ValueError('release identity or file list differs')
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as stream:
        raw = limited(stream, MAX_ARCHIVE)
    files = {}
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
        for member in tar:
            name = member.name
            if name in seen:
                raise ValueError(f'duplicate member: {name}')
            seen.add(name)
            if (name not in FILES or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or member.sparse is not None or not 0 <= member.size <= MAX_FILE):
                raise ValueError(f'unexpected member: {name}')
            data = tar.extractfile(member).read()
            if digest(data) != hashes[name]:
                raise ValueError(f'file hash differs: {name}')
            files[name] = data
    if set(files) != FILES:
        raise ValueError('missing archive members')
    return files, digest(archive)


@contextmanager
def directory(path):
    """Walk from root without following symlinks and pin the final directory."""
    path = path.absolute()
    if '..' in path.parts:
        raise ValueError('parent traversal in destination')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def write_at(fd, name, data, mode):
    with os.fdopen(os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                           mode, dir_fd=fd), 'wb') as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), mode)


@contextmanager
def new_dir(parent, name):
    os.mkdir(name, mode=0o700, dir_fd=parent)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


def stage(bundle, target, commit, version):
    files, checksum = verify(bundle, commit, version)
    with directory(target.parent) as parent, new_dir(parent, target.name) as root:
        with ExitStack() as stack:
            dirs = {Path('.'): root}
            for path in DIRECTORIES:
                dirs[path] = stack.enter_context(new_dir(dirs[path.parent], path.name))
            for name, data in files.items():
                path = Path(name)
                write_at(dirs[path.parent], path.name, data, 0o755 if name == 'src/flow_ui.py' else 0o600)
        receipt = dict(source_commit=commit, version=version, archive_sha256=checksum, file_count=len(files))
        write_at(root, 'STAGE_RECEIPT.json', (json.dumps(receipt, indent=2) + '\n').encode(), 0o600)


def render_plugin(stage_dir):
    flow = stage_dir / 'src'
    source = stage_dir / PLUGIN_SOURCE
    helper = flow / 'flow_bar.py'
    version = json.loads((stage_dir / 'STAGE_RECEIPT.json').read_text())['version']
    if not re.fullmatch(VERSION_PATTERN, version) or not helper.is_file():
        raise ValueError('incomplete plugin stage or invalid version')
    manifest = json.loads((source / 'manifest.json').read_bytes())
    manifest['version'] = version.removeprefix('v')
    # Use a distinct QML component URL when the top-level plugin symlink changes.
    manifest['entryPoints']['barWidget'] = version + '/FlowWidget.qml'
    qml = (source / 'FlowWidget.qml.in').read_text()
    qml = qml.replace('"@BAR_HELPER@"', json.dumps(str(helper)))
    command = 'exec ' + shlex.quote(str(flow / 'flow_ui.py'))
    qml = qml.replace('"@OPEN_SETTINGS@"', json.dumps(command))
    return version, json.dumps(manifest, indent=2) + '\n', qml


def render(stage_dir, python, out):
    for path in (stage_dir, python, out):
        if not re.fullmatch(r'/[A-Za-z0-9_@.+/-]+', str(path)) or '..' in path.parts:
            raise ValueError('use absolute paths containing only unit-safe characters')
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError('Python must be executable')
    flow = stage_dir / 'src'
    bundle = render_plugin(stage_dir)
    with directory(out.parent) as parent, new_dir(parent, out.name) as dest:
        for name in ('omarchy-flow.service', 'omarchy-flow.desktop'):
            template = (stage_dir / 'packaging' / (name + '.in')).read_text()
            unit = template.replace('@FLOW_DIR@', str(flow)).replace('@PYTHON_BIN@', str(python))
            write_at(dest, name, unit.encode(), 0o600)
        rule = '70-omarchy-flow.rules'
        write_at(dest, rule, (stage_dir / 'packaging' / rule).read_bytes(), 0o600)
        version, manifest, qml = bundle
        with new_dir(dest, 'omarchy-plugin') as plugins, new_dir(plugins, PLUGIN_ID) as plugin:
            with new_dir(plugin, version) as code:
                write_at(code, 'FlowWidget.qml', qml.encode(), 0o600)
            write_at(plugin, 'manifest.json', manifest.encode(), 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='operation', required=True)
    for operation in ('build', 'verify', 'stage'):
        sub = subs.add_parser(operation)
        sub.add_argument('--bundle', required=True, type=Path)
        sub.add_argument('--commit', required=True)
        sub.add_argument('--version', required=True)
        if operation == 'stage':
            sub.add_argument('--target', required=True, type=Path)
    sub = subs.add_parser('render-units')
    for arg in ('--stage', '--python', '--out'):
        sub.add_argument(arg, required=True, type=Path)
    args = parser.parse_args()
    if args.operation == 'render-units':
        render(args.stage, args.python, args.out)
        return
    if not re.fullmatch('[0-9a-f]{40}', args.commit) or not re.fullmatch(
            VERSION_PATTERN, args.version):
        parser.error('expected full commit SHA and vMAJOR.MINOR.PATCH with optional prerelease or build metadata')
    if args.operation == 'stage':
        stage(args.bundle, args.target, args.commit, args.version)
    else:
        {'build': build, 'verify': verify}[args.operation](args.bundle, args.commit, args.version)


if __name__ == '__main__':
    main()
