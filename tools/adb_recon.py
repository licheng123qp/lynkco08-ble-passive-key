#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
领克数字钥匙侦察脚本 —— 基于 adb 的设备侧信息采集

用法：
    python tools/adb_recon.py doctor           # 检查设备连接与调试授权
    python tools/adb_recon.py findpkg          # 查找领克 / 吉利 / 亿咖通系 APP
    python tools/adb_recon.py pullapk          # 拉取 APK（含 split）
    python tools/adb_recon.py hci on|off|pull  # 开关 / 导出蓝牙 HCI 日志
    python tools/adb_recon.py props            # 设备基本信息（型号/ROM/蓝牙能力）

说明：不只依赖包名，会按厂商关键字模糊匹配，避免包名猜错。
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADB = os.path.join(ROOT, "tools", "platform-tools", "adb.exe")
CAP = os.path.join(ROOT, "captures")

# 领克 / 吉利系常见包名关键字
KEYWORDS = ["lynk", "linkco", "geely", "ecarx", "zeekr", "lotus", "smart",
            "xingji", "flyme", "autolink", "geelyauto"]


def adb(*args, check=False, timeout=60):
    cmd = [ADB] + list(args)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        sys.exit(f"[错误] 找不到 adb：{ADB}")
    except subprocess.TimeoutExpired:
        sys.exit("[错误] adb 超时。检查数据线与手机解锁状态。")
    if check and p.returncode != 0:
        sys.exit(f"[错误] adb {' '.join(args)} 失败：\n{p.stderr.strip()}")
    return p.stdout + p.stderr


def shell(cmd, **kw):
    return adb("shell", cmd, **kw)


def device_ok():
    out = adb("devices")
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    if not lines:
        print("[×] 没有检测到设备。")
        print("    1) 用数据线连接手机（要能传输文件，不是只充电的线）")
        print("    2) 设置 → 关于手机 → 连点版本号 7 次 → 开发者选项")
        print("    3) 开发者选项 → 打开「USB 调试」")
        print("    4) 手机上弹出「允许 USB 调试吗？」→ 勾选始终允许 → 确定")
        return False
    if any("unauthorized" in l for l in lines):
        print("[!] 设备已连接，但未授权调试。")
        print("    看手机屏幕，点「允许」，并勾选「一律允许使用这台计算机进行调试」。")
        print("    没弹窗就拔掉重插，或在开发者选项里点「撤销 USB 调试授权」。")
        return False
    if any("offline" in l for l in lines):
        print("[!] 设备处于 offline。拔插一次数据线，或重启手机后重试。")
        return False
    print("[✓] 设备已连接：")
    for l in lines:
        print("    " + l)
    return True


def cmd_doctor():
    if not device_ok():
        return 1
    get = lambda k: shell(f"getprop {k}").strip()
    print("\n--- 设备信息 ---")
    print(f"厂商    : {get('ro.product.manufacturer')}")
    print(f"型号    : {get('ro.product.model')}")
    print(f"Android : {get('ro.build.version.release')} (SDK {get('ro.build.version.sdk')})")
    print(f"ROM     : {get('ro.build.display.id')}")
    print(f"MIUI/HyperOS: {get('ro.miui.ui.version.name') or '—'}")
    print(f"蓝牙 MAC: {get('ro.boot.btmacaddr') or '需 root 或系统设置查看'}")
    print("\n--- adb 权限 ---")
    who = shell("id").strip()
    print(f"shell uid: {who}")
    print("root 可用" if "uid=0" in who else "root 不可用（本阶段不需要）")

    out = shell("dumpsys bluetooth_manager | grep -i -E 'enabled|state' | head -5")
    print("\n--- 蓝牙状态 ---")
    print(out.strip() or "（读取失败）")

    ver = shell("ls /sdcard/btsnoop_hci.log 2>/dev/null && echo EXISTS")
    print(f"\n--- 现有 HCI 日志 ---\n{ver.strip() or '不存在（正常，说明还没开过）'}")
    return 0


def cmd_findpkg():
    if not device_ok():
        return 1
    out = shell("pm list packages -3")
    pkgs = sorted({m.split(":", 1)[1].strip()
                   for m in out.splitlines() if m.startswith("package:")})
    print(f"共 {len(pkgs)} 个第三方应用\n")
    hits = []
    for p in pkgs:
        low = p.lower()
        if any(k in low for k in KEYWORDS):
            hits.append(p)

    # 兜底：按 APP 名匹配（部分包名与品牌无关）
    if len(hits) < 1:
        print("包名里没匹配到品牌关键字，按应用名再找一遍…")
        for p in pkgs:
            label = shell(f"dumpsys package {p} | grep -i -m1 -E '非系统|label' ").strip()
            if re.search(r"领克|吉利|Lynk|Geely", label, re.I):
                hits.append(p)

    if not hits:
        print("[!] 没找到领克系应用。可能装在「应用分身」/工作资料里，")
        print("    也可能包名很特殊。请手动在设置里看应用详情确认包名。")
        return 1

    print("候选应用：")
    for p in hits:
        ver = shell(f"dumpsys package {p} | grep -m1 versionName").strip()
        ver = ver.split("=")[-1] if "=" in ver else (ver or "?")
        print(f"  · {p}   version={ver}")
    print("\n确认哪个是领克 APP 后，执行：python tools/adb_recon.py pullapk")
    return 0


def cmd_pullapk(only=None):
    if not device_ok():
        return 1
    os.makedirs(CAP, exist_ok=True)
    if only:
        cands = [only]
    else:
        out = shell("pm list packages -3")
        pkgs = [m.split(":", 1)[1].strip()
                for m in out.splitlines() if m.startswith("package:")]
        cands = [p for p in pkgs if any(k in p.lower() for k in KEYWORDS)]
    if not cands:
        print("[!] 未找到候选包，请先跑 findpkg 确认包名。")
        return 1

    if len(cands) > 1:
        print("检测到多个候选，将全部拉取：")
        for c in cands:
            print("  " + c)

    for pkg in cands:
        paths = [l.split(":", 1)[1].strip()
                 for l in shell(f"pm path {pkg}").splitlines() if l.startswith("package:")]
        if not paths:
            print(f"[!] {pkg} 取路径失败")
            continue
        print(f"\n=== {pkg}（{len(paths)} 个 APK）===")
        for i, remote in enumerate(paths):
            name = f"{pkg}" + ("" if i == 0 else f"__split{i}") + ".apk"
            local = os.path.join(CAP, name)
            r = adb("pull", remote, local)
            ok = "1 file pulled" in r or os.path.exists(local)
            print(f"  {'[✓]' if ok else '[×]'} {name}  <- {remote}")
    print(f"\n产物目录：{CAP}")
    print("下一步：把 APK 发我，或执行 python tools/adb_recon.py hci on 开始抓包。")
    return 0


def cmd_hci(action):
    if not device_ok():
        return 1
    if action == "on":
        shell("settings put global bluetooth_hci_log 1")
        # 部分 ROM 不认这个 key，提示手动开
        print("[✓] 已尝试写入 bluetooth_hci_log=1")
        print("⚠️ 关键：请到 开发者选项 确认「启用蓝牙 HCI 信息收集日志」已打开，")
        print("   然后【关闭蓝牙 → 再打开蓝牙】，否则不生效。")
        shell("svc bluetooth disable")
        shell("sleep 1; svc bluetooth enable")
        print("[✓] 已尝试重启蓝牙")
    elif action == "off":
        shell("settings put global bluetooth_hci_log 0")
        print("[✓] 已关闭")
    elif action == "pull":
        os.makedirs(CAP, exist_ok=True)
        found = False
        for remote in ("/sdcard/btsnoop_hci.log",
                       "/data/misc/bluetooth/logs/btsnoop_hci.log"):
            r = adb("pull", remote, os.path.join(CAP, "btsnoop_hci.log"))
            if "1 file pulled" in r:
                print(f"[✓] 已导出 {remote} -> captures/btsnoop_hci.log")
                found = True
                break
        if not found:
            print("[×] 没找到 btsnoop_hci.log。")
            print("    1) 确认开发者选项里的 HCI 日志开关已打开")
            print("    2) 打开后必须重启过蓝牙")
            print("    3) 用文件管理器到「内部存储」根目录手动看一眼")
            return 1
        print("\n下一步：python tools/btsnoop_analyze.py captures/btsnoop_hci.log")
    else:
        print("用法：python tools/adb_recon.py hci on|off|pull")
        return 1
    return 0


def cmd_props():
    if not device_ok():
        return 1
    keys = [
        "ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
        "ro.build.version.sdk", "ro.build.display.id", "ro.miui.ui.version.name",
        "ro.mi.os.version.name", "persist.sys.timezone",
    ]
    print("--- 属性 ---")
    for k in keys:
        v = shell(f"getprop {k}").strip()
        if v:
            print(f"{k:32s}= {v}")

    print("\n--- UWB 相关（判断本机是否有 UWB 硬件）---")
    uwb = shell("pm list features | grep -i uwb")
    print(uwb.strip() or "（未声明 UWB feature）")
    print("\n--- 蓝牙特性 ---")
    print(shell("pm list features | grep -i bluetooth").strip() or "（读取失败）")
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1].lower()
    if cmd == "doctor":
        return cmd_doctor()
    if cmd == "findpkg":
        return cmd_findpkg()
    if cmd == "pullapk":
        return cmd_pullapk(sys.argv[2] if len(sys.argv) > 2 else None)
    if cmd == "hci":
        return cmd_hci(sys.argv[2] if len(sys.argv) > 2 else "")
    if cmd == "props":
        return cmd_props()
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
