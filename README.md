# Omarchy Flow

[简体中文](README.zh-CN.md) · [Protocol notes](PROTOCOL.md) · [Release and rollback](docs/release-pipeline.md)

Move a Logitech mouse between an Omarchy desktop and a Mac running Logi Options+ by pushing the pointer against a screen edge. A linked keyboard can follow the mouse. This independent MIT-licensed community project is unaffiliated with Logitech and the Omarchy project.

Logitech, Logi, Logi Bolt, and Logi Options+ are trademarks or registered trademarks of Logitech Europe S.A. and/or its affiliates.

## What works

- Screen crossing on Hyprland, including multi-monitor edges, layout selection and optional modifier hold.
- Keyboard Link, peer discovery and synchronized Flow settings.
- Clipboard text, images, files and folders over authenticated peer connections, with transfer limits and a private local cache.
- GTK settings and an optional Omarchy Shell bar widget in English and Simplified Chinese. Choose **More settings → Language**. The bar picks up the selection on its next refresh.

Desktop screenshots will be added during dogfooding.

## Requirements

The release target is x86_64 Omarchy (Arch Linux), Hyprland on Wayland and Python 3.14. Use a Logitech Bolt receiver (USB ID `046d:c548`), a Flow-capable mouse paired to both computers, and Logi Options+ on the Mac. Physical crossing has been observed with the MX Master 3S B and a linked K865. Other combinations need hardware reports. Bluetooth-only setups use a different backend (`BleppBus` on macOS). Linux device access in this release uses Bolt.

Install system PyGObject, GTK 4, Libadwaita and wl-clipboard. ImageMagick enables additional input image formats. The widget requires Omarchy Shell and QuickShell. The user installer needs Bash, a Python installation with venv/pip, and a GitHub CLI with immutable-release verification. Keep both peers on a trusted LAN.

## Install a release

From a reviewed checkout matching the release, run as your desktop user:

```bash
scripts/install.sh install --version v0.1.0 --with-bar-widget
scripts/install.sh status
```

The installer verifies the GitHub release attestation, every asset and the checksums, then creates a version-specific environment under `~/.local/share/omarchy-flow/releases/`. It prints any administrative setup for you to review. Use `--dry-run` to preview or `--no-bar-widget` to omit the widget. Upgrades retain older versions.

For an Arch package, build the included recipe once the matching immutable release is public:

```bash
cd packaging/aur
makepkg -si
```

The package uses Arch's Python dependencies. Its runtime is in `/usr/lib/omarchy-flow`. Choose one installation method per user so user units do not shadow the system package.

### Receiver and firewall

The packaged udev rule grants the active seat access to the receiver management interface and mouse event node. The Arch package installs it automatically. For the user install, review and run:

```bash
sudo install -m 0644 packaging/70-omarchy-flow.rules /etc/udev/rules.d/70-omarchy-flow.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

A local `/etc/udev/rules.d/70-omarchy-flow.rules` overrides the packaged copy. Inspect any legacy `/etc/udev/rules.d/90-omarchy-flow.rules`. Verify the active desktop user can access the receiver with the new rule before retiring the legacy file, then reload and recheck access.

Reconnect the receiver if seat permissions have not refreshed. On a UFW-filtered LAN, check existing entries with `sudo ufw status` and add missing inbound rules for each trusted peer:

```bash
read -r -p 'Trusted peer IPv4 address: ' peer
sudo ufw allow from "$peer" to any port 59869 proto tcp
sudo ufw allow from "$peer" to any port 59870:59871 proto udp
```

### Start Flow

Switch the paired devices to their Linux channels and provision once. For the user install:

```bash
root="${XDG_DATA_HOME:-$HOME/.local/share}/omarchy-flow/current"
"$root/venv/bin/python" "$root/src/flow_daemon.py" provision
systemctl --user daemon-reload
systemctl --user enable --now omarchy-flow.service
```

For the Arch package, provision using `/usr/bin/python3 /usr/lib/omarchy-flow/flow_daemon.py provision`, then run the same systemd commands. Enable Flow in Options+ and search for the other computer. Open **Omarchy Flow** in the application launcher to edit the layout, enable a peer or inspect connection status. Re-provision after changing Easy-Switch channels.

### Add the bar widget

The user installer can register the widget with `--with-bar-widget`. For the Arch package, register it once:

```bash
id=io.github.alexwangyang.omarchy-flow
config=${XDG_CONFIG_HOME:-}
[[ $config == /* ]] || config=$HOME/.config
plugins="$config/omarchy/plugins"
mkdir -p "$plugins"
ln -s "/usr/share/omarchy-flow/omarchy-plugin/$id" "$plugins/$id"
```

After registration, run `omarchy-shell shell rescanPlugins`, then `omarchy plugin enable io.github.alexwangyang.omarchy-flow`. Left-click for status and settings, middle-click to refresh, or right-click to toggle Flow. When migrating from `local.omarchy.flow`, record its placement, disable it and enable the new ID. Keep the old link until the new widget works.

## Architecture and limitations

The daemon authenticates discovery, establishes encrypted peer tunnels and coordinates layout and clipboard transfers. Hyprland provides pointer geometry, and HID++ changes the active device channel. The GTK app and QuickShell widget use a per-user Unix socket to query and update the daemon. Device state lives in `omarchy-flow/state.json` under an absolute `XDG_CONFIG_HOME`, with `~/.config` as the fallback. Completed file transfers live in `~/.cache/omarchy-flow/transfers/`.

Options+ 2.9.1013853 on macOS 27.2.1 can leave incoming files or folders with a `.pending` suffix. The macOS paste-location notification is suppressed before Options+ requests file contents. Text and image transfers use other paths. See the [protocol observations](PROTOCOL.md).

For offline installation, upgrade, removal and rollback, follow the [release guide](docs/release-pipeline.md).
