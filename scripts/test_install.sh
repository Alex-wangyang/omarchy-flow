#!/usr/bin/env bash
# Linux integration test. Supply a verified offline bundle including wheels.
set -euo pipefail
umask 077
bundle=$(realpath -- "${1:?bundle directory}")
version=$(jq -er .version "$bundle/release.json")
commit=$(jq -er .source_commit "$bundle/release.json")
installer=$(realpath -- "$(dirname -- "$0")/install.sh")
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export HOME=$scratch/home XDG_CONFIG_HOME=$scratch/config XDG_DATA_HOME=$scratch/data
export UV_CACHE_DIR=$scratch/uv-cache XDG_CACHE_HOME=$scratch/cache
export XDG_RUNTIME_DIR=$scratch/runtime DBUS_SESSION_BUS_ADDRESS=unix:path=$scratch/missing-bus
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME/omarchy-flow" "$scratch/bin"
config=$XDG_CONFIG_HOME/omarchy-flow
current=$XDG_DATA_HOME/omarchy-flow/current
unit=$XDG_CONFIG_HOME/systemd/user/omarchy-flow.service
desktop=$XDG_DATA_HOME/applications/omarchy-flow.desktop
touch "$config/preserve"
install=(install --bundle "$bundle" --version "$version" --commit "$commit" --with-bar-widget)
reject() {
    if "$@" > "$scratch/error" 2>&1; then echo "unexpected success: $*" >&2; exit 1; fi
}

"$installer" "${install[@]}" > "$scratch/guidance"
first=$(readlink "$current")
test "$(stat -c %a "$XDG_DATA_HOME/omarchy-flow")" = 700
test "$(stat -c %a "$XDG_DATA_HOME/omarchy-flow/releases")" = 700
printf 'damaged\n' > "$first/src/flow_daemon.py"
printf 'damaged\n' > "$first/units/omarchy-flow.service"
parser=$("$first/venv/bin/python" -IB -c 'import pycparser; print(pycparser.__file__)')
[[ $parser == "$first/venv/"* ]]
printf 'raise RuntimeError("damaged")\n' > "$parser"
rm "$first/venv/bin/python"
"$installer" "${install[@]}"
test "$(readlink "$current")" != "$first"
(cd "$current" && jq -r '.files | to_entries[] | "\(.value)  \(.key)"' "$bundle/release.json" | sha256sum --check --status)
grep -Fq "$(readlink "$current")/src/flow_daemon.py" "$unit"
"$current/venv/bin/python" -IB -c 'import cryptography, _cffi_backend, pycparser'
"$installer" status | grep -F "Configuration directory: $config"
XDG_CONFIG_HOME=relative "$installer" status | grep -F "Configuration directory: $HOME/.config/omarchy-flow"

# The real user-bus query must fail closed even with a missing selector.
selected=$(readlink "$current")
rm "$current"
reject "$installer" uninstall --purge
grep -F 'unable to query systemd' "$scratch/error"
[[ -L $unit && -d $selected && -f $config/preserve ]]
ln -s "$selected" "$current"

# Model the inactive manager without touching a user's running service.
cat > "$scratch/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
[[ $* == '--user show omarchy-flow.service -p ActiveState -p LoadState -p FragmentPath' ]] || exit 2
if [[ ! -L $XDG_CONFIG_HOME/systemd/user/omarchy-flow.service ]]; then
    printf 'LoadState=not-found\nActiveState=inactive\nFragmentPath=\n'
    exit 0
fi
printf 'LoadState=loaded\nActiveState=%s\nFragmentPath=%s\n' "${TEST_STATE:-inactive}" "${TEST_FRAGMENT:-$XDG_CONFIG_HOME/systemd/user/omarchy-flow.service}"
STUB
chmod 700 "$scratch/bin/systemctl"
export PATH=$scratch/bin:$PATH
TEST_STATE=active reject "$installer" uninstall
TEST_FRAGMENT=/usr/lib/systemd/user/omarchy-flow.service reject "$installer" uninstall --purge
other_config=$scratch/other-config
mkdir -p "$other_config/omarchy-flow"
touch "$other_config/omarchy-flow/keep"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall --purge
grep -F 'different XDG config/registration root' "$scratch/error"
[[ -f $other_config/omarchy-flow/keep && -L $current && -L $unit && -d $selected && -f $config/preserve ]]
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall
[[ -L $current && -L $unit && -d $selected ]]
XDG_CONFIG_HOME=$other_config reject "$installer" "${install[@]}"
[[ -L $current && -L $unit && -d $selected ]]
rm "$current"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall --purge
[[ -f $other_config/omarchy-flow/keep && ! -L $current && -L $unit && -L $desktop && -d $selected ]]
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall
[[ ! -L $current && -L $unit && -L $desktop && -d $selected ]]
XDG_CONFIG_HOME=$other_config reject "$installer" "${install[@]}"
[[ ! -L $current && -L $unit && -L $desktop && -d $selected ]]
cp "$selected/.installer-complete" "$scratch/meta.bak"
cp "$selected/STAGE_RECEIPT.json" "$scratch/receipt.bak"
printf '{invalid\n' > "$selected/.installer-complete"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall --purge
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall
XDG_CONFIG_HOME=$other_config reject "$installer" "${install[@]}"
[[ -f $other_config/omarchy-flow/keep && ! -L $current && -L $unit && -L $desktop && -d $selected ]]
printf '{invalid\n' > "$selected/STAGE_RECEIPT.json"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall --purge
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall
XDG_CONFIG_HOME=$other_config reject "$installer" "${install[@]}"
[[ -f $other_config/omarchy-flow/keep && ! -L $current && -L $unit && -L $desktop && -d $selected ]]
mv -f "$scratch/receipt.bak" "$selected/STAGE_RECEIPT.json"
ln -s "$selected" "$current"
XDG_CONFIG_HOME=$other_config reject "$installer" "${install[@]}"
reject "$installer" "${install[@]}"
reject "$installer" uninstall
mv -f "$scratch/meta.bak" "$selected/.installer-complete"
mv "$desktop" "$scratch/desktop"
touch "$desktop"
reject "$installer" uninstall
[[ -L $unit && -d $selected ]]
mv -T "$scratch/desktop" "$desktop"
chmod 750 "$XDG_DATA_HOME/omarchy-flow/releases"
reject "$installer" "${install[@]}"
chmod 700 "$XDG_DATA_HOME/omarchy-flow/releases"
foreign=$XDG_DATA_HOME/omarchy-flow/releases/v1.0.0
mkdir "$foreign"
touch "$foreign/.installer-complete" "$foreign/STAGE_RECEIPT.json"
"$installer" uninstall
test -d "$foreign"
[[ ! -L $current && ! -L $unit && ! -L $desktop && ! -e $selected && ! -e $first && -f $config/preserve ]]
reject "$installer" uninstall --purge
grep -F "no registered managed install" "$scratch/error"
test -f "$config/preserve"
"$installer" "${install[@]}"
only=$(readlink "$current")
rm "$current"
cp "$only/.installer-complete" "$scratch/only-meta.bak"
cp "$only/STAGE_RECEIPT.json" "$scratch/only-receipt.bak"
printf '{invalid\n' > "$only/.installer-complete"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall --purge
grep -F 'corrupt or incomplete install metadata' "$scratch/error"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall
grep -F 'corrupt or incomplete install metadata' "$scratch/error"
XDG_CONFIG_HOME=$other_config reject "$installer" "${install[@]}"
grep -F 'corrupt or incomplete install metadata' "$scratch/error"
[[ -f $other_config/omarchy-flow/keep && ! -L $current && -L $unit && -L $desktop && -d $only ]]
printf '{invalid\n' > "$only/STAGE_RECEIPT.json"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall --purge
grep -F 'existing desktop registration has no matching managed install' "$scratch/error"
XDG_CONFIG_HOME=$other_config reject "$installer" uninstall
grep -F 'existing desktop registration has no matching managed install' "$scratch/error"
XDG_CONFIG_HOME=$other_config reject "$installer" "${install[@]}"
grep -F 'existing desktop registration has no matching managed install' "$scratch/error"
[[ -f $other_config/omarchy-flow/keep && ! -L $current && -L $unit && -L $desktop && -d $only ]]
mv -f "$scratch/only-meta.bak" "$only/.installer-complete"
mv -f "$scratch/only-receipt.bak" "$only/STAGE_RECEIPT.json"
ln -s "$only" "$current"
# Mixed layout: a managed parent stage containing a nested release with valid receipt but corrupt metadata.
mixed=$XDG_DATA_HOME/omarchy-flow/releases/$version
mkdir -p "$mixed/release"
cp "$only/STAGE_RECEIPT.json" "$mixed/STAGE_RECEIPT.json"
jq --arg stage "$mixed" '.stage = $stage' "$only/.installer-complete" > "$mixed/.installer-complete"
cp "$only/STAGE_RECEIPT.json" "$mixed/release/STAGE_RECEIPT.json"
printf '{invalid\n' > "$mixed/release/.installer-complete"
reject "$installer" uninstall
grep -F "corrupt or incomplete install metadata in $mixed/release" "$scratch/error"
reject "$installer" "${install[@]}"
grep -F "corrupt or incomplete install metadata in $mixed/release" "$scratch/error"
[[ -d $mixed/release && -L $current && -L $unit ]]
rm -rf "$mixed"
"$installer" uninstall --purge > "$scratch/removal"
grep -Fx "Configuration directory: $config" "$scratch/removal"
test ! -e "$config"
test -f "$other_config/omarchy-flow/keep"
echo 'Installer integration tests passed.'
