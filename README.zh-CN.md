# Omarchy Flow

[English](README.md) · [协议笔记](PROTOCOL.md) · [发布与回滚](docs/release-pipeline.md)

用一只罗技鼠标操作 Omarchy 桌面和运行 Logi Options+ 的 Mac。将指针推向屏幕边缘即可切换电脑，开启「链接键盘」后键盘也会随鼠标切换。本项目由社区独立维护，采用 MIT 许可证，与罗技及 Omarchy 项目无隶属关系。

Logitech、Logi、Logi Bolt 和 Logi Options+ 均为 Logitech Europe S.A. 和／或其关联公司的商标或注册商标。

## 功能与环境

- 支持 Hyprland 多显示器边缘切换、布局同步和按住修饰键切换。
- 支持电脑发现、链接键盘，以及通过已认证连接共享文本、图片、文件和文件夹。
- GTK 设置窗口和可选的 Omarchy Shell 状态栏组件均支持英文和简体中文。在「更多设置 → 语言」中切换，组件会在下次刷新时跟随。桌面截图将在实际试用期间补充。

目标平台为 x86_64 Omarchy（Arch Linux）、Hyprland/Wayland 和 Python 3.14。需要 USB ID 为 `046d:c548` 的 Logitech Bolt 接收器、已在两台电脑配对的 Flow 鼠标，以及 Mac 上的 Logi Options+。已观察到 MX Master 3S B 和 K865 联动切换。其他组合欢迎提交实测记录。纯蓝牙连接使用另一套后端，macOS 端涉及 `BleppBus`；当前 Linux 端通过 Bolt 访问设备。

安装系统 PyGObject、GTK 4、Libadwaita 和 wl-clipboard。ImageMagick 可扩展输入图片格式。状态栏组件使用 Omarchy Shell 和 QuickShell。用户安装器需要 Bash、包含 venv/pip 的 Python，以及支持不可变 Release 验证的 GitHub CLI。两台电脑应位于可信局域网。

## 安装

在与版本对应且已经审核的源码目录，以桌面用户执行：

```bash
scripts/install.sh install --version v0.1.0 --with-bar-widget
scripts/install.sh status
```

安装器校验 GitHub Release 签名证明、三个附件及其摘要，再创建独立的版本目录和虚拟环境。可用 `--dry-run` 预览，用 `--no-bar-widget` 跳过状态栏组件。升级时会保留旧版。

也可以在对应的不可变 Release 公开后构建 Arch 软件包：

```bash
cd packaging/aur
makepkg -si
```

软件包使用 Arch 系统依赖，程序位于 `/usr/lib/omarchy-flow`。每个用户选一种安装方式，避免用户服务遮盖系统软件包的服务文件。

### 接收器权限与防火墙

udev 规则只向当前活动桌面用户授予 Bolt 管理接口和鼠标事件节点的访问权限。Arch 软件包已包含规则，用户安装方式需自行审核后执行：

```bash
sudo install -m 0644 packaging/70-omarchy-flow.rules /etc/udev/rules.d/70-omarchy-flow.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

`/etc/udev/rules.d/70-omarchy-flow.rules` 优先于软件包的同名规则。若存在旧的 `/etc/udev/rules.d/90-omarchy-flow.rules`，先检查其内容，验证新规则已向当前活动桌面用户授予接收器访问权限，再停用旧规则、重新加载并复核权限。

若权限还未生效，可重新插拔接收器。启用 UFW 的电脑可先用 `sudo ufw status` 检查现有规则，再为每个可信对端补齐入站规则：

```bash
read -r -p '可信对端的 IPv4 地址：' peer
sudo ufw allow from "$peer" to any port 59869 proto tcp
sudo ufw allow from "$peer" to any port 59870:59871 proto udp
```

### 首次启动

将鼠标和键盘切到 Linux 通道。用户安装方式执行：

```bash
root="${XDG_DATA_HOME:-$HOME/.local/share}/omarchy-flow/current"
"$root/venv/bin/python" "$root/src/flow_daemon.py" provision
systemctl --user daemon-reload
systemctl --user enable --now omarchy-flow.service
```

使用 Arch 软件包时，登记设备的命令为 `/usr/bin/python3 /usr/lib/omarchy-flow/flow_daemon.py provision`，随后执行相同的 systemd 命令。在 Options+ 启用 Flow 并搜索另一台电脑。通过应用启动器打开 **Omarchy Flow** 可以调整布局、启用对端和查看连接状态。更改 Easy-Switch 通道后需要重新登记。

### 状态栏组件

用户安装器可通过 `--with-bar-widget` 注册组件。Arch 软件包用户执行一次：

```bash
id=io.github.alexwangyang.omarchy-flow
config=${XDG_CONFIG_HOME:-}
[[ $config == /* ]] || config=$HOME/.config
plugins="$config/omarchy/plugins"
mkdir -p "$plugins"
ln -s "/usr/share/omarchy-flow/omarchy-plugin/$id" "$plugins/$id"
```

执行 `omarchy-shell shell rescanPlugins` 重新扫描，再用 `omarchy plugin enable io.github.alexwangyang.omarchy-flow` 启用。左键打开面板，中键刷新，右键切换 Flow。已有 `local.omarchy.flow` 时，先记下位置，停用旧组件后启用新 ID，验证后再移除旧链接。

## 架构与已知限制

后台服务负责认证、加密连接、布局和剪贴板传输。Hyprland 提供指针位置和显示器几何信息，HID++ 负责切换设备通道。GTK 窗口和状态栏组件使用当前用户的 Unix 套接字访问后台服务。设备配置写入 `omarchy-flow/state.json`。若 `XDG_CONFIG_HOME` 是绝对路径，就使用该目录，否则使用 `~/.config`。接收的文件存放在 `~/.cache/omarchy-flow/transfers/`。

macOS 27.2.1 上的 Options+ 2.9.1013853 接收文件或文件夹时可能停留在 `.pending`。系统抑制了粘贴目的地通知，Options+ 因此尚未请求文件内容。文本和图片使用不同的传输流程。详见[协议笔记](PROTOCOL.md)。

离线安装、升级、卸载与回滚请参阅[发布指南](docs/release-pipeline.md)。
