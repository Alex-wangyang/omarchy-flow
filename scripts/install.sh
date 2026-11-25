#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    cat <<'HELP'
scripts/install.sh install --version vX.Y.Z [--commit FULL_SHA] [--with-bar-widget|--no-bar-widget] [--dry-run]
scripts/install.sh install --bundle DIR --version vX.Y.Z --commit FULL_SHA [same options]
scripts/install.sh status
scripts/install.sh uninstall [--purge] [--dry-run]

With --bundle, put compatible locked wheels in DIR/wheels for offline installation.
Without --bundle, GitHub CLI verifies the immutable release and each asset.
Installation registers user files. Start or restart the service after provisioning.
HELP
}
die() { echo "omarchy-flow: $*" >&2; exit 1; }
action=${1:-help}
[[ $# == 0 ]] || shift
version='' commit='' bundle='' widget=auto dry=false purge=false
while (($#)); do
    case "$1" in
        --version|--commit|--bundle)
            [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "missing value for $1"
            case "$1" in --version) version=$2;; --commit) commit=$2;; --bundle) bundle=$2;; esac
            shift 2;;
        --with-bar-widget) widget=yes; shift;;
        --no-bar-widget) widget=no; shift;;
        --dry-run) dry=true; shift;;
        --purge) purge=true; shift;;
        *) die "unknown option $1";;
    esac
done
case "$action" in
    help|-h|--help) usage; exit 0;;
    install) [[ $purge == false ]] || die "--purge is for uninstall"
        num='(0|[1-9][0-9]*)'
        label="($num|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
        build='[0-9A-Za-z-]+'
        semver="^v$num\\.$num\\.$num(-$label(\\.$label)*)?(\\+$build(\\.$build)*)?$"
        [[ $version =~ $semver ]] || die "invalid version"
        [[ -z $commit || $commit =~ ^[0-9a-f]{40}$ ]] || die "invalid commit"
        [[ -z $bundle || -n $commit ]] || die "offline bundle requires an independent commit SHA";;
    status|uninstall)
        [[ -z $version && -z $commit && -z $bundle && $widget == auto ]] || die "unexpected install option"
        [[ $action != status || $purge == false && $dry == false ]] || die "status takes no options";;
    *) usage >&2; exit 2;;
esac

repo=Alex-wangyang/omarchy-flow
tool="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/release.py"
data=${XDG_DATA_HOME:-"$HOME/.local/share"}
config=${XDG_CONFIG_HOME:-}
[[ $config == /* ]] || config=$HOME/.config
for path in "$data" "$config"; do
    [[ $path =~ ^/[A-Za-z0-9_@.+/-]+$ && /$path/ != */../* ]] || die "expected an absolute unit-safe XDG path"
done
data=$(realpath -ms -- "$data")
config=$(realpath -ms -- "$config")
base=$data/omarchy-flow
releases=$base/releases
config_dir=$config/omarchy-flow
[[ $base != /usr/lib/omarchy-flow && $config_dir != /usr/lib/omarchy-flow ]] || die 'reserved Arch package path'
[[ $config_dir != "$base" && $config_dir/ != "$base/"* && $base/ != "$config_dir/"* ]] || die 'install and configuration directories overlap'
id=io.github.alexwangyang.omarchy-flow
unit=$config/systemd/user/omarchy-flow.service
desktop=$data/applications/omarchy-flow.desktop
plugin=$config/omarchy/plugins/$id
legacy=$config/omarchy/plugins/local.omarchy.flow
current=$base/current
owned_link() { [[ -L $1 && $(stat -c %u -- "$1") == "$EUID" && $(readlink -- "$1") == "$2" ]]; }
exists() { [[ -e $1 || -L $1 ]]; }
managed_stage() {
    [[ -d $1 && ! -L $1 && -O $1 && -f $1/.installer-complete && ! -L $1/.installer-complete &&
       -O $1/.installer-complete && -f $1/STAGE_RECEIPT.json && ! -L $1/STAGE_RECEIPT.json && -O $1/STAGE_RECEIPT.json ]] || return 1
    python3 -IB - "$1" <<'PY'
import json, re, sys
from pathlib import Path

stage = Path(sys.argv[1])
num = r'(?:0|[1-9][0-9]*)'
label = rf'(?:{num}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
build = r'[0-9A-Za-z-]+'
ver_re = rf'v{num}\.{num}\.{num}(?:-{label}(?:\.{label})*)?(?:\+{build}(?:\.{build})*)?'
try:
    receipt = json.loads((stage / "STAGE_RECEIPT.json").read_bytes())
    meta = json.loads((stage / ".installer-complete").read_bytes())
    version = receipt["version"]
    name = stage.parent.name if stage.name == "release" else stage.name
    keys = ("stage", "config_dir", "unit", "desktop", "plugin")
    valid = (isinstance(version, str)
             and re.fullmatch(ver_re, version)
             and (name == version or stage.name == "release" and name.startswith(version + "."))
             and isinstance(receipt["source_commit"], str)
             and re.fullmatch("[0-9a-f]{40}", receipt["source_commit"])
             and isinstance(receipt["archive_sha256"], str)
             and re.fullmatch("[0-9a-f]{64}", receipt["archive_sha256"])
             and isinstance(meta, dict)
             and meta.get("schema") == "omarchy-flow-install-v1"
             and all(isinstance(meta.get(k), str) and meta[k].startswith("/") for k in keys)
             and meta["stage"] == str(stage.resolve()))
except (OSError, ValueError, KeyError, TypeError):
    valid = False
sys.exit(0 if valid else 1)
PY
}
stage_matches_binding() {
    python3 -IB - "$1" "$config_dir" "$unit" "$desktop" "$plugin" <<'PY'
import json, sys
from pathlib import Path

stage, config_dir, unit, desktop, plugin = sys.argv[1:6]
try:
    meta = json.loads((Path(stage) / ".installer-complete").read_bytes())
    ok = (meta.get("schema") == "omarchy-flow-install-v1"
          and meta.get("stage") == str(Path(stage).resolve())
          and meta.get("config_dir") == config_dir
          and meta.get("unit") == unit
          and meta.get("desktop") == desktop
          and meta.get("plugin") == plugin)
except (OSError, ValueError, TypeError):
    ok = False
sys.exit(0 if ok else 1)
PY
}
valid_stage_receipt() {
    [[ -d $1 && ! -L $1 && -O $1 && -f $1/STAGE_RECEIPT.json && ! -L $1/STAGE_RECEIPT.json && -O $1/STAGE_RECEIPT.json ]] || return 1
    python3 -IB - "$1" <<'PY'
import json, re, sys
from pathlib import Path

stage = Path(sys.argv[1])
num = r'(?:0|[1-9][0-9]*)'
label = rf'(?:{num}|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
build = r'[0-9A-Za-z-]+'
ver_re = rf'v{num}\.{num}\.{num}(?:-{label}(?:\.{label})*)?(?:\+{build}(?:\.{build})*)?'
try:
    receipt = json.loads((stage / "STAGE_RECEIPT.json").read_bytes())
    version = receipt["version"]
    name = stage.parent.name if stage.name == "release" else stage.name
    valid = (isinstance(version, str)
             and re.fullmatch(ver_re, version)
             and (name == version or stage.name == "release" and name.startswith(version + "."))
             and isinstance(receipt["source_commit"], str)
             and re.fullmatch("[0-9a-f]{40}", receipt["source_commit"])
             and isinstance(receipt["archive_sha256"], str)
             and re.fullmatch("[0-9a-f]{64}", receipt["archive_sha256"]))
except (OSError, ValueError, KeyError, TypeError):
    valid = False
sys.exit(0 if valid else 1)
PY
}
if [[ $action == status || $purge == true ]]; then printf 'Configuration directory: %s\n' "$config_dir"; fi
if [[ $action == status ]]; then
    if [[ -L $current ]]; then
        printf 'Selected release: %s\n' "$(readlink -- "$current")"
        cat -- "$current/STAGE_RECEIPT.json"
    else echo 'No user-installed release selected.'; fi
    if owned_link "$plugin" "$current/units/omarchy-plugin/$id"; then echo 'Widget registered.'; fi
    if [[ -L $legacy ]]; then echo "Legacy widget link: $legacy"; fi
    exit 0
fi
[[ $(uname -sm) == 'Linux x86_64' ]] || die "requires x86_64 Linux"
check_stopped() {
    local state
    state=$(systemctl --user show omarchy-flow.service -p ActiveState -p LoadState -p FragmentPath) ||
        die 'unable to query systemd user service state; preserving the installation'
    grep -Fxq 'ActiveState=inactive' <<< "$state" &&
        grep -Exq 'LoadState=(loaded|not-found)' <<< "$state" ||
        die 'uninstall requires a confirmed inactive or absent service'
    fragment=$(sed -n 's/^FragmentPath=//p' <<< "$state")
}
if [[ $dry == true ]]; then
    if [[ $action == uninstall ]]; then check_stopped; fi
    printf '%s (dry run), install root %s, version %s, widget %s, purge %s\n' "$action" "$base" "$version" "$widget" "$purge"
    if [[ -n $bundle ]]; then python3 -B "$tool" verify --bundle "$bundle" --version "$version" --commit "$commit"; fi
    exit 0
fi

# A root-owned sticky directory (such as /tmp) protects entries owned by this user.
check_parents() {
    local path=$1 uid mode
    while [[ $path != / ]]; do
        if exists "$path"; then
            [[ -d $path && ! -L $path ]] || die "unsafe directory: $path"
            read -r uid mode < <(stat -c '%u %a' -- "$path")
            (( uid == EUID || uid == 0 )) || die "directory owned by another user: $path"
            (( (8#$mode & 0022) == 0 || (uid == 0 && (8#$mode & 01000)) )) || die "writable ancestor: $path"
        fi
        path=$(dirname -- "$path")
    done
}
private_root() {
    check_parents "$1"
    [[ ! -d $1 || $(stat -c '%u:%a' -- "$1") == "$EUID:700" ]] || die "expected owner-only (0700) directory: $1"
}
fragment=''
private_root "$base"
if [[ $action == uninstall && ! -d $base ]]; then
    check_stopped
    [[ $purge == false ]] || die "no managed install; preserving $config_dir"
    echo 'No managed install found.'
    exit 0
fi

# The base directory is retained so waiters always lock the same inode.
mkdir -p -- "$base"
exec {lock_fd}<"$base"
flock -x "$lock_fd"
private_root "$base"
if [[ $action == uninstall ]]; then check_stopped; fi
private_root "$releases"
for item in "$unit" "$desktop" "$plugin"; do check_parents "$(dirname -- "$item")"; done
previous=''
if exists "$current"; then
    [[ -L $current && $(stat -c %u -- "$current") == "$EUID" ]] || die "unmanaged current path: $current"
    previous=$(readlink -- "$current")
    rel=${previous#"$releases/"}
    [[ $previous == "$releases/$rel" && $rel =~ ^v[0-9A-Za-z.+-]+(/release)?$ ]] ||
        die "unmanaged release selector: $current"
    check_parents "$previous"
    if managed_stage "$previous"; then
        stage_matches_binding "$previous" ||
            die "existing installation is bound to a different XDG config/registration root; preserving $config_dir and existing registrations"
    elif [[ $action != install ]] || exists "$previous/.installer-complete" ||
        ! owned_link "$unit" "$current/units/omarchy-flow.service"; then
        die "missing or invalid installer ownership: $previous"
    fi
fi
shopt -s nullglob
managed=()
for item in "$releases"/v*; do
    [[ -d $item && ! -L $item && -O $item ]] || continue
    for candidate in "$item" "$item/release"; do
        [[ -d $candidate && ! -L $candidate && -O $candidate ]] || continue
        if managed_stage "$candidate"; then
            managed+=("$candidate")
        elif valid_stage_receipt "$candidate"; then
            die "corrupt or incomplete install metadata in $candidate; inspect before modifying $base"
        fi
    done
done
for item in "${managed[@]}"; do
    stage_matches_binding "$item" ||
        die "managed release $item is bound to a different XDG config/registration root; preserving $config_dir and existing registrations"
done
if (( ${#managed[@]} == 0 )) && [[ -z $previous ]] && exists "$desktop" &&
    ! owned_link "$unit" "$current/units/omarchy-flow.service"; then
    die "existing desktop registration has no matching managed install for $config_dir; inspect $desktop and $releases"
fi
if [[ $action == uninstall ]]; then
    if [[ $fragment == "$unit" ]] && ! owned_link "$unit" "$current/units/omarchy-flow.service"; then
        die "unmanaged service registration: $unit"
    fi
    if [[ -n $fragment && $fragment != "$unit" ]]; then
        found=false
        for item in "${managed[@]}"; do
            if [[ $fragment == "$item/units/omarchy-flow.service" ]]; then found=true; fi
        done
        [[ $found == true ]] || die "service belongs to another installation: $fragment"
    fi
    links=()
    for item in "$unit" "$desktop" "$plugin"; do
        case "$item" in
            "$unit") target=$current/units/omarchy-flow.service;;
            "$desktop") target=$current/units/omarchy-flow.desktop;;
            "$plugin") target=$current/units/omarchy-plugin/$id;;
        esac
        if exists "$item"; then
            owned_link "$item" "$target" || die "unmanaged registration: $item"
            links+=("$item")
        fi
    done
    if [[ $purge == true ]]; then
        (( ${#managed[@]} )) && [[ -n $previous || ${#links[@]} -gt 0 ]] ||
            die "no registered managed install; preserving $config_dir"
        check_parents "$config_dir"
        [[ ! -d $config_dir || -O $config_dir ]] || die "unmanaged config: $config_dir"
    fi
    for item in "${links[@]}"; do rm -- "$item"; done
    if [[ -n $previous ]]; then rm -- "$current"; fi
    for item in "${managed[@]}"; do
        rm -rf --one-file-system -- "$item"
        if [[ $item == */release ]]; then rmdir --ignore-fail-on-non-empty -- "$(dirname -- "$item")"; fi
    done
    if [[ $purge == true ]]; then rm -rf --one-file-system -- "$config_dir"; fi
    echo 'User install removed. Run systemctl --user daemon-reload to refresh systemd.'
    exit 0
fi

mkdir -p -- "$releases"
private_root "$releases"
pending_stage='' stage='' added=()
scratch=$(mktemp -d "$base/.install.XXXXXXXX")
cleanup() {
    if [[ -n $pending_stage ]] && ! owned_link "$current" "$stage"; then
        for item in "${added[@]}"; do rm -f -- "$item"; done
        rm -rf -- "$pending_stage"
    fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT
if [[ -z $bundle ]]; then
    bundle=$scratch/bundle
    mkdir -- "$bundle"
    gh api "repos/$repo/releases/tags/$version" | python3 -c '
import json, sys
r = json.load(sys.stdin)
if not (r["immutable"] and not r["draft"] and sorted(a["name"] for a in r["assets"]) ==
        ["SHA256SUMS", "omarchy-flow.tar.gz", "release.json"]):
    sys.exit("unexpected release state or assets")'
    sha=$(gh api "repos/$repo/commits/$version" --jq .sha)
    [[ -z $commit || $commit == "$sha" ]] || die "release tag differs from expected commit"
    commit=$sha
    gh release verify "$version" -R "$repo"
    gh release download "$version" -R "$repo" -D "$bundle" -p SHA256SUMS -p release.json -p omarchy-flow.tar.gz
    for asset in SHA256SUMS release.json omarchy-flow.tar.gz; do
        gh release verify-asset "$version" "$bundle/$asset" -R "$repo"
    done
    pip_args=()
else
    bundle=$(cd -- "$bundle" && pwd -P)
    pip_args=(--no-index --find-links "$bundle/wheels")
fi
args=(--bundle "$bundle" --version "$version" --commit "$commit")
python3 -B "$tool" verify "${args[@]}"
ensure_link() {
    local dest=$1 target=$2
    if owned_link "$dest" "$target"; then return; fi
    if exists "$dest"; then die "preserve existing path: $dest (inspect and back it up before migration)"; fi
    mkdir -p -- "$(dirname -- "$dest")"
    ln -s -- "$target" "$dest"
    added+=("$dest")
}
# Venv launchers and rendered units contain absolute paths. Keep this generation
# in its original directory and atomically publish only the selector.
pending_stage=$(mktemp -d "$releases/$version.XXXXXXXX")
stage=$pending_stage/release
python3 -B "$tool" stage "${args[@]}" --target "$stage"
if command -v uv >/dev/null; then
    /usr/bin/python3 -m venv --without-pip "$stage/venv"
    uv pip install --require-hashes --only-binary=:all: --no-cache --link-mode=copy --python "$stage/venv/bin/python" "${pip_args[@]}" -r "$stage/requirements.lock"
    uv pip check --python "$stage/venv/bin/python"
else
    /usr/bin/python3 -m venv "$stage/venv"
    "$stage/venv/bin/python" -m pip --isolated --disable-pip-version-check install --require-hashes --only-binary=:all: "${pip_args[@]}" -r "$stage/requirements.lock"
    "$stage/venv/bin/python" -m pip --disable-pip-version-check check
fi
"$stage/venv/bin/python" -IB -c 'import _cffi_backend, pycparser; from cryptography.hazmat.primitives.asymmetric import ec; ec.generate_private_key(ec.SECP256R1())'
python3 -B "$tool" render-units --stage "$stage" --python "$stage/venv/bin/python" --out "$stage/units"
grep -Fq "ExecStart=$stage/venv/bin/python -u $stage/src/flow_daemon.py" "$stage/units/omarchy-flow.service"
grep -Fq "$stage/src/flow_ui.py" "$stage/units/omarchy-flow.desktop"
if grep -RE '@[A-Za-z_][A-Za-z0-9_]*@' "$stage/units"; then die 'unresolved packaging token'; fi
python3 -IB - "$stage" "$config_dir" "$unit" "$desktop" "$plugin" <<'PY'
import json, os, sys
from pathlib import Path

stage, config_dir, unit, desktop, plugin = sys.argv[1:6]
meta = {
    "schema": "omarchy-flow-install-v1",
    "stage": str(Path(stage).resolve()),
    "config_dir": config_dir,
    "unit": unit,
    "desktop": desktop,
    "plugin": plugin,
}
fd = os.open(Path(stage) / ".installer-complete",
             os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "wb") as stream:
    stream.write((json.dumps(meta, indent=2, sort_keys=True) + "\n").encode())
PY
ensure_link "$unit" "$current/units/omarchy-flow.service"
ensure_link "$desktop" "$current/units/omarchy-flow.desktop"
if [[ $widget == yes ]]; then ensure_link "$plugin" "$current/units/omarchy-plugin/$id"; fi
ln -s -- "$stage" "$scratch/selector"
mv -Tf -- "$scratch/selector" "$current"
pending_stage=''
added=()
if [[ $widget == no ]] && owned_link "$plugin" "$current/units/omarchy-plugin/$id"; then rm -- "$plugin"; fi
if [[ -L $legacy ]]; then
    echo "Legacy widget found at $legacy. Record its placement, disable local.omarchy.flow, then enable $id. Remove the old symlink after checking the new widget."
fi
rule=70-omarchy-flow.rules
if exists /etc/udev/rules.d/90-omarchy-flow.rules; then
    echo 'Inspect legacy /etc/udev/rules.d/90-omarchy-flow.rules and retire it after validating active-seat access with 70-omarchy-flow.rules.'
fi
effective_rule=/usr/lib/udev/rules.d/$rule
if exists "/etc/udev/rules.d/$rule"; then effective_rule=/etc/udev/rules.d/$rule; fi
if ! cmp -s "$stage/units/$rule" "$effective_rule"; then
    printf 'sudo install -m 0644 %q %q && sudo udevadm control --reload-rules && sudo udevadm trigger\n' "$stage/units/$rule" "/etc/udev/rules.d/$rule"
fi
cat <<'GUIDANCE'
If UFW filters this LAN, check sudo ufw status and add any missing peer rules:
read -r -p 'Trusted peer IPv4 address: ' peer
sudo ufw allow from "$peer" to any port 59869 proto tcp
sudo ufw allow from "$peer" to any port 59870:59871 proto udp
GUIDANCE
printf 'Selected %s. Provision with %q %q provision, then run systemctl --user daemon-reload and systemctl --user enable --now omarchy-flow.service. To activate an upgrade, run systemctl --user restart omarchy-flow.service.\n' "$version" "$stage/venv/bin/python" "$stage/src/flow_daemon.py"
