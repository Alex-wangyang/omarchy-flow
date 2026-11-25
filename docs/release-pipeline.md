# Release, installation and rollback

The target is x86_64 Omarchy with Python 3.14. The daemon uses the pinned dependencies in requirements.lock. The GTK launcher and QuickShell helper use the system interpreter. Release tags use SemVer 2.0.0 (`vMAJOR.MINOR.PATCH` with optional prerelease or build metadata).

## Build a candidate

Review the main commit and its public contents. scripts/release.py reads an exact allowlist from Git objects. It packages the license, both READMEs, protocol notes, lock file, 15 runtime modules, 10 test modules and 5 packaging templates or assets. The archive is independent of checkout timestamps. release.json records its file hashes, release version, repository and full source SHA under schema omarchy-flow-release-v2. SHA256SUMS covers the archive and manifest.

```bash
sha=$(git rev-parse HEAD)
version=v0.1.0
work=$(mktemp -d)
args=(--bundle "$work/bundle" --commit "$sha" --version "$version")
python3 scripts/release.py build "${args[@]}"
python3 scripts/release.py verify "${args[@]}"
python3 scripts/release.py stage "${args[@]}" --target "$work/stage"
python3 -m venv "$work/stage/venv"
"$work/stage/venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r "$work/stage/requirements.lock"
python3 scripts/release.py render-units --stage "$work/stage" --python "$work/stage/venv/bin/python" --out "$work/stage/units"
(cd "$work/stage" && PYTHONPATH=src venv/bin/python -B -m unittest discover -s tests -p 'test_*.py')
```

On Omarchy also run systemd-analyze --user verify on the rendered service and omarchy-plugin-validate on the rendered io.github.alexwangyang.omarchy-flow directory with OMARCHY_PATH=/usr/share/omarchy. Its manifest must point to the version-specific FlowWidget.qml. Run the system Python GTK/GUI tests with gtk4-broadwayd and check the widget in both languages on an isolated display.

## Publish

Merge reviewed source and require CI to pass. As a mandatory operator preflight before every dispatch, run the following command with repository Administration read access and proceed only if it prints `true`.

```bash
gh api repos/Alex-wangyang/omarchy-flow/immutable-releases --jq .enabled
```

The standard Actions `GITHUB_TOKEN` cannot request Administration read access through workflow permissions and can receive HTTP 403 from this endpoint. To repeat the preflight in Actions, set the optional repository secret `IMMUTABLE_PREFLIGHT_TOKEN` to a fine-grained PAT scoped to this repository with Administration read access. When configured, an API error or any value other than `true` stops publication.

Dispatch release.yml on main with the new version, its exact expected_source_sha and the prerelease flag. Set the flag for tags with a prerelease suffix and clear it for stable tags. The workflow uploads the assets to a draft, verifies the complete set and publishes it in one operation. It immediately reads back the release and deletes the release and tag if GitHub reports a mutable release. It checks the tag commit, immutable flag, prerelease flag, exact asset names and GitHub release attestations. Retain the workflow run, release ID and asset digests. If publication is interrupted, inspect the existing release before retrying. A published version is permanent.

The AUR recipe pins the archive digest. For a new stable version, build its candidate, update pkgver and sha256sums, check the packaged paths and run makepkg --printsrcinfo. Verify the digest against the published archive before submitting the recipe and generated .SRCINFO to the AUR.

## Install and upgrade

Use scripts/install.sh from a reviewed checkout. Online installation uses the explicit release tag, checks its immutable state, verifies its attestation and all three assets, and checks the manifest against the tag commit. Pass --commit to additionally pin a separately reviewed SHA. Locked binary wheels may be downloaded during installation.

For an offline machine, first verify the GitHub release and its three assets on a connected machine. Carry them together in one bundle directory. Prepare matching x86_64 Linux wheels for the target interpreter in its wheels subdirectory:

```bash
python3 -m pip download --require-hashes --only-binary=:all: -r requirements.lock -d "$bundle/wheels"
scripts/install.sh install --bundle "$bundle" --version "$version" --commit "$sha" --dry-run
scripts/install.sh install --bundle "$bundle" --version "$version" --commit "$sha" --with-bar-widget
```

Offline checksum verification relies on the bundle's trusted handoff. The lock file pins SHA-256 digests for compatible Linux wheels. The installer uses uv when available and otherwise uses venv pip. The installer registers systemd, desktop and optional widget links and selects the candidate through a single current symlink. Each installation builds a fresh generation in the private releases directory, including when reinstalling the same version. The selector changes only after verification. Older generations remain available to a running service until it restarts. It leaves provisioning, service activation and privileged udev/firewall setup to the operator. Existing regular files and unrelated links at integration paths need manual review before installation.

Record the previous version, commit, bundle and service state before upgrading. Finish current transfers, install the new version, run systemctl --user daemon-reload and restart the service. Check systemctl --user status omarchy-flow.service, its ExecStart/MainPID, the UI's peer state and the widget. Verify physical crossings and clipboard contents separately with both operators present.

## Rollback and removal

To roll back, run the installer for the previous verified version and commit, reload systemd and restart. Confirm the rendered paths resolve to the old version. If a release changes persistent data formats, check compatibility and restore an appropriate backup before activation.

Before uninstalling, disable the widget in Omarchy and run systemctl --user disable --now omarchy-flow.service. Then run scripts/install.sh uninstall and systemctl --user daemon-reload. The uninstaller removes its own registered links and managed releases. Configuration and received files are preserved. Each installed generation records its resolved configuration and registration paths; uninstall and --purge refuse to proceed if XDG_CONFIG_HOME no longer matches the recorded installation. For a matching registered user install, --purge prints and removes the configuration directory under that XDG_CONFIG_HOME (or, by default, ~/.config). An unavailable systemd user bus or conflicting registration stops removal. System-wide rules installed manually can be reviewed and removed separately.

An existing `/etc/udev/rules.d/70-omarchy-flow.rules` takes precedence over the packaged rule in `/usr/lib/udev/rules.d`. Inspect any legacy `/etc/udev/rules.d/90-omarchy-flow.rules`, verify active-seat receiver access with the new rule, then retire the legacy file, reload the rules and recheck access.
