#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ELF / APK 字符串侦察器

从 native 库里挖出协议线索：GATT UUID、加密算法名、密钥存储痕迹、状态机常量。

用法：
    python tools/apk_strings.py captures/lynkco_4.2.8.apk --extract     # 先提取目标 so
    python tools/apk_strings.py --lib libglble.so                        # 扫单个 so
    python tools/apk_strings.py --lib libglble.so --grep "unlock|auth"   # 关键词过滤
    python tools/apk_strings.py --dex                                   # 扫 dex 里的 UUID
"""

import argparse
import os
import re
import struct
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(ROOT, "work")
APK = os.path.join(ROOT, "captures", "lynkco_4.2.8.apk")

# 优先分析的目标（体积小、和数字钥匙相关）
TARGETS = [
    "lib/arm64-v8a/libglble.so",
    "lib/arm64-v8a/libwhite-box.so",
    "lib/arm64-v8a/libecc256.so",
    "lib/arm64-v8a/libZeekrSecurity.so",
    "lib/arm64-v8a/libEncryptorP.so",
    "lib/arm64-v8a/liblogsecurity.so",
    "lib/arm64-v8a/libkadp.so",
]

UUID_RE = re.compile(
    r"(?:0000[0-9a-fA-F]{4}|[0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# 分组的关注词
GROUPS = {
    "BLE/GATT": r"gatt|bluetooth|ble_|_ble|advertis|characteristic|notify|indicate|mtu|rssi|scan",
    "钥匙/业务": r"unlock|lock|door|key_|_key|digitalkey|dk_|vehicle|vin|pair|bind",
    "认证/会话": r"auth|session|token|challenge|nonce|counter|seq|handshake|verify|sign",
    "密码算法": r"\baes\b|\bsm[234]\b|hmac|cmac|ecc|secp256|ecdh|sha256|crc|whitebox|white-box|kdf|hkdf",
    "密钥存储": r"keystore|keymaster|strongbox|androidkey|secure_?element|\btee\b|obfuscat",
    "协议帧": r"frame|packet|payload|header|cmd|command|opcode|checksum|magic",
}


def printable_strings(data, minlen=4):
    """同时抽取 ASCII 与 UTF-16LE 字符串。"""
    out = set()
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.add(m.group().decode("ascii", "ignore"))
    # UTF-16LE
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        s = m.group().decode("utf-16-le", "ignore")
        if s.isprintable():
            out.add(s)
    return out


def extract_targets():
    os.makedirs(WORK, exist_ok=True)
    z = zipfile.ZipFile(APK)
    names = set(z.namelist())
    for t in TARGETS:
        if t not in names:
            print(f"[!] 不存在：{t}")
            continue
        dest = os.path.join(WORK, os.path.basename(t))
        with z.open(t) as src, open(dest, "wb") as dst:
            dst.write(src.read())
        print(f"[✓] {os.path.basename(t):28s} {os.path.getsize(dest)/1e6:7.2f} MB")
    print(f"\n产物：{WORK}")


def elf_info(path):
    """读 ELF 头，判断架构与是否有符号表。"""
    with open(path, "rb") as f:
        h = f.read(64)
    if h[:4] != b"\x7fELF":
        return None
    bits = "64" if h[4] == 2 else "32"
    endian = "LE" if h[5] == 1 else "BE"
    return f"ELF{bits} {endian}"


def scan(path, grep=None, show_uuids=True):
    name = os.path.basename(path)
    data = open(path, "rb").read()
    print(f"\n{'='*70}\n{name}  ({len(data)/1e6:.2f} MB, {elf_info(path)})\n{'='*70}")

    strs = printable_strings(data)

    if show_uuids:
        uuids = sorted({s for s in strs if UUID_RE.fullmatch(s)})
        if uuids:
            print(f"\n[UUID] 发现 {len(uuids)} 个：")
            for u in uuids:
                print(f"  {u}")
        else:
            print("\n[UUID] 未发现完整 UUID 字符串（可能以字节数组形式硬编码）")

    for gname, pat in GROUPS.items():
        rx = re.compile(pat, re.I)
        hits = sorted(s for s in strs if rx.search(s) and len(s) < 120)
        if not hits:
            continue
        print(f"\n[{gname}] {len(hits)} 条")
        for s in hits[:40]:
            print(f"  {s}")
        if len(hits) > 40:
            print(f"  … 另有 {len(hits)-40} 条")

    if grep:
        rx = re.compile(grep, re.I)
        hits = sorted(s for s in strs if rx.search(s))
        print(f"\n[自定义过滤 /{grep}/] {len(hits)} 条")
        for s in hits[:120]:
            print(f"  {s}")


def scan_dex():
    """在 dex 里找 UUID 与关键字符串。dex 很大，流式扫描。"""
    z = zipfile.ZipFile(APK)
    names = [n for n in z.namelist() if n.endswith(".dex")]
    print(f"扫描 {names}")
    uuid_hits = set()
    kw_hits = set()
    for n in names:
        with z.open(n) as f:
            data = f.read()
        for m in UUID_RE.finditer(data.decode("latin-1")):
            uuid_hits.add(m.group())
        for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
            s = m.group().decode("ascii", "ignore")
            low = s.lower()
            if any(k in low for k in ("uwb", "gatt", "digitalkey", "digital_key",
                                      "whitebox", "strongbox", "androidkeystore")):
                kw_hits.add(s)
    print(f"\n[DEX UUID] {len(uuid_hits)} 个：")
    for u in sorted(uuid_hits):
        print(f"  {u}")
    print(f"\n[DEX 关键词] {len(kw_hits)} 条：")
    for s in sorted(kw_hits)[:80]:
        print(f"  {s}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", nargs="?", help="APK 路径（默认用 captures/lynkco_4.2.8.apk）")
    ap.add_argument("--extract", action="store_true", help="提取目标 so 到 work/")
    ap.add_argument("--lib", nargs="+", help="要扫描的 so（work/ 下的文件名或完整路径）")
    ap.add_argument("--grep", help="自定义正则过滤")
    ap.add_argument("--dex", action="store_true", help="扫描 dex")
    args = ap.parse_args()

    if args.extract:
        extract_targets()
        return 0

    if args.dex:
        scan_dex()
        return 0

    if args.lib:
        for l in args.lib:
            p = l if os.path.isabs(l) or os.path.exists(l) else os.path.join(WORK, l)
            if not os.path.exists(p):
                print(f"[!] 找不到 {p}")
                continue
            scan(p, grep=args.grep)
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
