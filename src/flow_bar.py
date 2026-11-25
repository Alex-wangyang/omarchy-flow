#!/usr/bin/python3
"""Small, stdlib-only JSON client for the Omarchy shell widget."""
import argparse
import json
import sys

from flow_control import ControlClient, RESCAN_TIMEOUT, RPC_TIMEOUT

from flow_i18n import display_summary, load_ui_language, safe_summary, tr

SWITCHES = ("on", "copy_paste", "keyboard_link", "ctrl_key")
EVENTS = {"Discovery", "Flow IN", "Flow OUT", "Flow SWITCH", "Settings sync"}


def display_name(value):
    if not isinstance(value, str):
        return ""
    return "".join(c if c.isprintable() else " " for c in value[:64]).strip()


def project(status, lang="en"):
    """Project the socket reply onto display fields. Never forward whole records."""
    settings = status["settings"] or {}
    host = display_name(status["host_id"])
    channel = status["local_channel"]
    local_enabled = not settings
    peers = []
    for row in settings.get("peers", [])[:3]:
        if row["is_local"]:
            local_enabled = row["enabled"] is True and row["host_id"] == status["host_id"]
        elif row["host_id"]:
            peers.append(dict(host_id=display_name(row["host_id"]), enabled=row["enabled"] is True,
                              connected=row["connected"] is True))
    flags = {key: settings.get(key, key == "on") is True for key in SWITCHES}
    clip = status.get("clipboard") or {}
    summary = safe_summary(clip.get("last_summary"))
    modifier = status["preferences"]["modifier_key"]
    recent = []
    for event in status.get("events", [])[-15:]:
        if isinstance(event, str):
            category = event.partition("  ")[2].partition(" · ")[0]
            if category in EVENTS:
                recent.append(category)
    return {
        "online": True,
        "language": lang,
        "host_id": host,
        "local_channel": channel if type(channel) is int and channel in (0, 1, 2) else None,
        "active_owner": display_name(status.get("active_owner")) or None,
        "local_enabled": local_enabled,
        "flow_on": local_enabled and flags["on"],
        "settings": flags,
        "peers": peers,
        "preferences": {"modifier_key": modifier if modifier in ("ctrl", "super", "alt") else None},
        "mouse": display_name((status.get("mouse") or {}).get("name")),
        "keyboard": display_name((status.get("keyboard") or {}).get("name")),
        "clipboard": {"enabled": clip.get("enabled") is True, "busy": clip.get("busy") is True,
                      "last_summary": summary, "display_summary": display_summary(lang, summary)},
        "events": recent[-5:],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    edit = commands.add_parser("set-setting")
    edit.add_argument("key", choices=SWITCHES)
    edit.add_argument("value", choices=("on", "off"))
    commands.add_parser("rescan")
    args = parser.parse_args(argv)
    timeout = {"status": 2, "set-setting": RPC_TIMEOUT + 1, "rescan": RESCAN_TIMEOUT + 1}
    client = ControlClient(timeout=timeout[args.command])
    lang = load_ui_language()
    exit_code = 0
    try:
        if args.command == "set-setting":
            # The daemon merges a single explicit value into its current settings.
            status = client.call("update_settings", **{args.key: args.value == "on"})
        elif args.command == "rescan":
            status = client.call("rescan_devices")
        else:
            status = client.call("get_status")
        result = project(status, lang)
        if status.get("delivery_errors"):
            result["notice"] = tr(lang, "Saved locally. A peer did not confirm.")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        # Socket errors and future protocol details must never reach the bar or journal.
        if args.command == "status":
            result = {"online": False, "language": lang}
        else:
            result = {"language": lang, "notice": tr(lang, "Action unconfirmed. Refreshing status.")}
            exit_code = 1
    finally:
        client.close()
    print(json.dumps(result, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
