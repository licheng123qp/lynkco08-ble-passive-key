#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 APK 的 AndroidManifest，重点输出 exported 组件与 intent-filter。
用途：找官方 APP 有没有能被外部（或 root）直接触发的解锁入口。
"""
import sys
import os

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def main():
    apk_path = sys.argv[1] if len(sys.argv) > 1 else "captures/lynkco_4.2.8.apk"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "work/manifest.txt"

    import zipfile
    from xml.etree import ElementTree as ET
    from androguard.core.axml import AXMLPrinter

    print(f"[*] 解析 {apk_path} ({os.path.getsize(apk_path)/1e6:.0f} MB) ...")
    with zipfile.ZipFile(apk_path) as z:
        raw_xml = z.read("AndroidManifest.xml")

    # 保留未解码的资源引用（@0x7f... 形式）
    printer = AXMLPrinter(raw_xml)
    root = ET.fromstring(printer.get_xml())

    pkg = root.get("package")
    ver_name = root.get(ANDROID_NS + "versionName")
    ver_code = root.get(ANDROID_NS + "versionCode")
    uses_sdk = root.find("uses-sdk")
    min_sdk = uses_sdk.get(ANDROID_NS + "minSdkVersion") if uses_sdk is not None else "?"
    tgt_sdk = uses_sdk.get(ANDROID_NS + "targetSdkVersion") if uses_sdk is not None else "?"

    print(f"[+] package = {pkg}")
    print(f"[+] versionName = {ver_name} ({ver_code})")
    print(f"[+] minSdk={min_sdk} targetSdk={tgt_sdk}")

    lines = []
    w = lines.append

    w(f"# {pkg} {ver_name} ({ver_code})")
    w(f"minSdk={min_sdk} targetSdk={tgt_sdk}")

    # ---- uses-permission ----
    perms = [e.get(ANDROID_NS + "name") for e in root.iter("uses-permission")]
    w(f"\n## uses-permission ({len(perms)})")
    for p in perms:
        w(f"  {p}")

    # ---- application 属性 ----
    app = root.find("application")
    if app is not None:
        keys = ("name", "debuggable", "usesCleartextTraffic",
                "allowBackup", "networkSecurityConfig")
        w("\n## application")
        for k in keys:
            v = app.get(ANDROID_NS + k)
            if v is not None:
                w(f"  {k} = {v}")

    # ---- 组件 ----
    COMP = ("activity", "activity-alias", "service", "receiver", "provider")
    exported_list = []

    for tag in COMP:
        elems = list(root.iter(tag))
        if not elems:
            continue
        w(f"\n## {tag} ({len(elems)})")
        for e in elems:
            name = e.get(ANDROID_NS + "name") or "?"
            exp = e.get(ANDROID_NS + "exported")
            perm = e.get(ANDROID_NS + "permission")
            actions = []
            cats = []
            for f in e.iter("intent-filter"):
                for act in f.iter("action"):
                    actions.append(act.get(ANDROID_NS + "name") or "")
                for c in f.iter("category"):
                    cats.append(c.get(ANDROID_NS + "name") or "")
            flag = ""
            if exp == "true":
                flag = " [EXPORTED]"
                exported_list.append((tag, name, actions, perm))
            elif exp == "false":
                flag = " [private]"
            else:
                # 未显式声明：有 intent-filter 则默认 true（targetSdk<31）
                flag = " [default+if]" if actions else ""
            w(f"  {name}{flag}")
            if perm:
                w(f"      permission: {perm}")
            if actions:
                w(f"      actions: {', '.join(x for x in actions if x)[:200]}")
            if cats:
                w(f"      cats: {', '.join(x for x in cats if x)[:120]}")

    # ---- 摘要 ----
    w(f"\n## 摘要：显式 exported 组件 ({len(exported_list)})")
    for tag, name, actions, perm in exported_list:
        w(f"  [{tag}] {name}")
        if perm:
            w(f"        perm={perm}")
        if actions:
            w(f"        actions={actions}")

    txt = "\n".join(lines)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(txt)
    print(f"[+] 写出 {out_path} ({len(lines)} 行)")


if __name__ == "__main__":
    main()
