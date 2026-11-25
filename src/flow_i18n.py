"""Local UI language, shared by the settings window and the shell helper."""
from pathlib import Path
import re

from flow_control import default_config_dir, private_dir, read_private_json, write_private_json

LANGUAGES = ("en", "zh")
DEFAULT_LANGUAGE = "en"


def ui_preferences_path():
    return default_config_dir() / "ui.json"


def load_ui_language(path=None):
    path = Path(path) if path is not None else ui_preferences_path()
    try:
        with private_dir(path.parent, create=False) as directory:
            value = read_private_json(directory, path.name, limit=1024)
        if isinstance(value, dict) and value.get("language") in LANGUAGES:
            return value["language"]
    except (OSError, ValueError, RecursionError):
        pass
    return DEFAULT_LANGUAGE


def save_ui_language(lang, path=None):
    if lang not in LANGUAGES:
        raise ValueError("unsupported UI language")
    path = Path(path) if path is not None else ui_preferences_path()
    with private_dir(path.parent) as directory:
        write_private_json(directory, path.name, {"language": lang})


ZH = {
    "Connecting": "正在连接",
    "More settings": "更多设置",
    "Connecting to the Flow service": "正在连接 Flow 服务",
    "Retry connection": "重试连接",
    "Layout": "排布方式",
    "Horizontal": "水平",
    "Vertical": "垂直",
    "Top left": "左上",
    "Top right": "右上",
    "Bottom left": "左下",
    "Bottom right": "右下",
    "Local displays and crossing edges": "本机屏幕与穿越边缘",
    "Left edge": "左边缘",
    "Right edge": "右边缘",
    "Top edge": "上边缘",
    "Bottom edge": "下边缘",
    "Hold {key} at the edge": "按住 {key} 并将光标移到边缘",
    "Move the pointer to the edge": "将光标移到边缘",
    "No crossing edges": "暂无可穿越边缘",
    "No local display information": "暂无本机屏幕信息",
    "Flow settings": "Flow 设置",
    "Language": "语言",
    "Switch computers": "切换电脑",
    "Hold the modifier at the edge": "按住修饰键并将光标移到边缘",
    "Local modifier key": "本机修饰键",
    "Ctrl (Mac default)": "Ctrl（Mac 默认）",
    "Super (Win / Cmd)": "Super（Win / Cmd 键）",
    "Edge gestures": "边缘手势",
    "Edge pressure threshold": "边缘推力阈值",
    "Switch cooldown (seconds)": "切换冷却时间（秒）",
    "Copy & Paste": "复制和粘贴",
    "Keyboard Link": "链接键盘",
    "Rescan Bolt devices": "重新扫描 Bolt 设备",
    "Find other computers": "发现其他电脑",
    "Optional IP · 192.168.1.x": "可选 IP · 192.168.1.x",
    "Search local network": "搜索局域网电脑",
    "Reset Flow": "重置 Flow",
    "Reset Flow?": "重置 Flow？",
    "Remove this computer from the layout and sync the change to connected computers.":
        "将从当前排布中移除本机，并同步到已连接的电脑。",
    "Cancel": "取消",
    "Reset": "重置",
    "+ Add computer": "+ 添加电脑",
    "Move earlier": "前移一位",
    "Move later": "后移一位",
    "Disable": "禁用",
    "Enable": "启用",
    "Remove from Flow": "从 Flow 移除",
    "Local · Connected": "本机 · 已连接",
    "Disabled": "已禁用",
    "Connected": "已连接",
    "Offline": "离线",
    "This computer has not joined Flow": "本机未加入 Flow",
    "Transferring…": "传输中…",
    "Copy text, images, files and folders in both directions": "双向复制文本、图像、文件和文件夹",
    "Bolt mouse": "Bolt 鼠标",
    "Bolt keyboard": "Bolt 键盘",
    "No paired keyboard found": "未发现配对键盘",
    "Keyboard unlinked": "未链接键盘",
    "Connected to the Flow service": "已连接 Flow 服务",
    "Cannot connect to the local Flow service": "无法连接本机 Flow 服务",
    "Service offline": "服务离线",
    "Could not save the language preference": "无法保存语言设置",
    "Action could not be completed": "操作未完成",
    "Saved locally. No confirmation from {peers}.": "设置已保存，以下电脑尚未确认：{peers}",
    "Saved locally. A peer did not confirm.": "设置已保存，一台电脑尚未确认。",
    "Action unconfirmed. Refreshing status.": "操作尚未确认。正在刷新状态。",
    "No paired devices found": "未发现配对设备",
    "Searching the local network": "正在搜索局域网电脑",
    "Settings synced": "设置已同步",
    "Peer discovered": "已发现电脑",
    "Switched here": "已切换到本机",
    "Switched away": "已切换到其他电脑",
    "Channel switched": "已切换频道",
    "Flow activity": "Flow 活动",
}

# Only public messages from the control protocol may be shown in the error banner.
CONTROL_ERRORS = {
    "invalid peer slot": "无效的电脑位置",
    "select an occupied remote slot": "请选择已分配给其他电脑的位置",
    "unknown setting": "未知设置",
    "unknown preference": "未知偏好设置",
    "invalid modifier key": "无效的修饰键",
    "edge threshold must be 5..500": "边缘推力阈值必须在 5 到 500 之间",
    "edge cooldown must be 0.1..5": "切换冷却时间必须在 0.1 到 5 秒之间",
    "preferences path unavailable": "无法访问偏好设置文件",
    "three peer slots required": "需要三个电脑位置",
    "invalid peer fields": "电脑设置字段无效",
    "expected three unique peer channels": "三个电脑频道必须各不相同",
    "invalid peer values": "电脑设置值无效",
    "unknown host for channel": "此电脑与频道不匹配",
    "settings flags must be booleans": "开关设置无效",
    "unknown layout": "未知排布方式",
    "expected an owned private 0700 directory": "配置目录必须属于当前用户，权限为 0700",
    "expected an owned private 0600 file": "配置文件必须属于当前用户，权限为 0600",
    "settings changed; retry": "设置已更改，请重试",
    "activate keyboard locally and rescan": "请在本机激活键盘后重新扫描",
    "different keyboard linked by peer": "另一台电脑已链接不同的键盘",
    "expected IPv4 address": "请输入 IPv4 地址",
    "invalid request or operation unavailable": "请求无效或操作暂不可用",
    "control request timed out": "请求超时",
    "local peer must remain active": "本机必须保持启用",
    "empty slot cannot be enabled": "无法启用空位",
}

EDGES = {"LEFT": "Left edge", "RIGHT": "Right edge", "TOP": "Top edge", "BOTTOM": "Bottom edge"}


def tr(lang, message, **values):
    template = ZH.get(message, message) if lang == "zh" else message
    return template.format(**values) if values else template


# Only these measurement formats are public, even if future daemons add details.
SUMMARY = re.compile(
    r"Clipboard (?:IN|OUT) · (?:text \(\d+ B\)|image \(\d+x\d+\)|"
    r"\d+ files \(\d+(?:\.\d+)? (?:B|MiB)\)|\d+ files offered|file data served)", re.ASCII)


def safe_summary(value):
    if isinstance(value, str) and len(value) <= 96 and SUMMARY.fullmatch(value):
        return value
    return None


def display_summary(lang, value):
    summary = safe_summary(value)
    if not summary:
        return None
    if lang == "en":
        return summary.replace(" · 1 files", " · 1 file")
    direction, detail = summary.split(" · ")
    prefix = "剪贴板接收" if direction == "Clipboard IN" else "剪贴板发送"
    if detail.startswith("text "):
        detail = detail.replace("text", "文本")
    elif detail.startswith("image "):
        detail = detail.replace("image", "图像").replace("x", "×")
    elif detail.endswith("files offered"):
        detail = "已提供 " + detail.split()[0] + " 个文件"
    elif detail == "file data served":
        detail = "已发送文件数据"
    else:
        detail = detail.replace(" files", " 个文件")
    return prefix + " · " + detail


EVENT_NAMES = {"Settings sync": "Settings synced", "Flow IN": "Switched here",
               "Flow OUT": "Switched away", "Flow SWITCH": "Channel switched",
               "Discovery": "Peer discovered"}


def display_event(lang, event):
    stamp, sep, message = event.partition("  ")
    if not sep:
        stamp, message = "", event
    parts = message.split(" · ")
    if parts == ["Discovery", "search"]:
        parts = ["Searching the local network"]
    elif parts[0] in EVENT_NAMES:
        parts[0] = EVENT_NAMES[parts[0]]
    else:
        parts = ["Flow activity"]
    parts[0] = tr(lang, parts[0])
    for i, part in enumerate(parts[1:], start=1):
        if part in EDGES:
            parts[i] = tr(lang, EDGES[part])
    return stamp + sep + " · ".join(parts)
