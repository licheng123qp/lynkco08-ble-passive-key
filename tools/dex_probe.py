#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""轻量 DEX 解析器（纯标准库，为超大 dex 设计，按需解码字符串）。

能力：
  - 遍历 APK 内所有 classes*.dex
  - 按正则查找类名
  - 打印指定类的字段与方法（含签名、access flags、是否 native）
  - 定位方法体的 code_off（供后续反汇编）

用法：
  python tools/dex_probe.py classes <regex>
  python tools/dex_probe.py members <完整类名>
  python tools/dex_probe.py members <完整类名> --grep <正则>
"""
import sys
import re
import struct
import zipfile
import os
from functools import lru_cache

ACC_NAMES = [
    (0x0001, "public"), (0x0002, "private"), (0x0004, "protected"),
    (0x0008, "static"), (0x0010, "final"), (0x0020, "synchronized"),
    (0x0040, "volatile/bridge"), (0x0080, "transient/varargs"),
    (0x0100, "native"), (0x0200, "interface"), (0x0400, "abstract"),
    (0x0800, "strict"), (0x1000, "synthetic"), (0x2000, "annotation"),
    (0x4000, "enum"), (0x10000, "constructor"), (0x20000, "declared_sync"),
]


def acc_str(v):
    return " ".join(n for b, n in ACC_NAMES if v & b) or "0"


def uleb128(buf, off):
    """读 uleb128，返回 (value, new_off)"""
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


class DexFile:
    def __init__(self, data):
        self.b = data
        self.string_ids_size, self.string_ids_off = struct.unpack_from("<2I", data, 56)
        self.type_ids_size, self.type_ids_off = struct.unpack_from("<2I", data, 64)
        self.proto_ids_size, self.proto_ids_off = struct.unpack_from("<2I", data, 72)
        self.field_ids_size, self.field_ids_off = struct.unpack_from("<2I", data, 80)
        self.method_ids_size, self.method_ids_off = struct.unpack_from("<2I", data, 88)
        self.class_defs_size, self.class_defs_off = struct.unpack_from("<2I", data, 96)

    # ---------- 基础索引 ----------
    @lru_cache(maxsize=1 << 18)
    def string(self, idx):
        if idx >= self.string_ids_size:
            return ""
        so = struct.unpack_from("<I", self.b, self.string_ids_off + idx * 4)[0]
        _, p = uleb128(self.b, so)
        end = self.b.index(b"\x00", p)
        raw = self.b[p:end]
        try:
            return raw.decode("utf-8", "replace")
        except Exception:
            return raw.decode("latin-1", "replace")

    def type_str(self, idx):
        if idx == 0xFFFFFFFF or idx >= self.type_ids_size:
            return "?"
        si = struct.unpack_from("<I", self.b, self.type_ids_off + idx * 4)[0]
        return self.string(si)

    def type_display(self, idx):
        """Lcom/foo/Bar; -> com.foo.Bar"""
        t = self.type_str(idx)
        if t.startswith("L") and t.endswith(";"):
            return t[1:-1].replace("/", ".")
        return t

    def proto_str(self, idx):
        if idx >= self.proto_ids_size:
            return "?"
        _shorty, ret, params_off = struct.unpack_from(
            "<3I", self.b, self.proto_ids_off + idx * 12)
        parts = []
        if params_off:
            n = struct.unpack_from("<I", self.b, params_off)[0]
            for i in range(n):
                ti = struct.unpack_from("<H", self.b, params_off + 4 + i * 2)[0]
                parts.append(self.type_display(ti))
        return f"({','.join(parts)}){self.type_display(ret)}"

    def method_ref(self, idx):
        """返回 (class_display, name, proto)"""
        if idx >= self.method_ids_size:
            return ("?", "?", "?")
        ci, pi, ni = struct.unpack_from("<HHI", self.b, self.method_ids_off + idx * 8)
        return (self.type_display(ci), self.string(ni), self.proto_str(pi))

    def field_ref(self, idx):
        if idx >= self.field_ids_size:
            return ("?", "?", "?")
        ci, ti, ni = struct.unpack_from("<HHI", self.b, self.field_ids_off + idx * 8)
        return (self.type_display(ci), self.string(ni), self.type_display(ti))

    # ---------- 类 ----------
    def iter_class_defs(self):
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            (c_idx, acc, super_idx, _if, src_idx, _ann, cdata_off,
             _sv) = struct.unpack_from("<8I", self.b, off)
            yield c_idx, acc, super_idx, cdata_off

    def class_name(self, c_idx):
        return self.type_display(c_idx)

    def find_classes(self, rx):
        out = []
        for c_idx, acc, super_idx, cdata_off in self.iter_class_defs():
            n = self.class_name(c_idx)
            if rx.search(n):
                out.append((n, acc, self.type_display(super_idx), cdata_off))
        return out

    def class_members(self, c_idx, cdata_off):
        """返回 (static_fields, instance_fields, direct_methods, virtual_methods)"""
        b = self.b
        p = cdata_off
        sf, p = uleb128(b, p)
        inf, p = uleb128(b, p)
        dm, p = uleb128(b, p)
        vm, p = uleb128(b, p)

        def read_fields(n, p):
            res = []
            idx = 0
            for _ in range(n):
                diff, p = uleb128(b, p)
                acc, p = uleb128(b, p)
                idx += diff
                res.append((idx, acc))
            return res, p

        def read_methods(n, p):
            res = []
            idx = 0
            for _ in range(n):
                diff, p = uleb128(b, p)
                acc, p = uleb128(b, p)
                code_off, p = uleb128(b, p)
                idx += diff
                res.append((idx, acc, code_off))
            return res, p

        sfl, p = read_fields(sf, p)
        infl, p = read_fields(inf, p)
        dml, p = read_methods(dm, p)
        vml, p = read_methods(vm, p)
        return sfl, infl, dml, vml


def load_dex_files(apk):
    out = []
    with zipfile.ZipFile(apk) as z:
        for n in sorted(z.namelist()):
            if re.fullmatch(r"classes\d*\.dex", n):
                print(f"[*] 载入 {n} ({z.getinfo(n).file_size/1e6:.0f} MB)")
                out.append((n, DexFile(z.read(n))))
    return out


def cmd_classes(apk, pattern):
    rx = re.compile(pattern, re.I)
    total = 0
    for name, dex in load_dex_files(apk):
        hits = dex.find_classes(rx)
        if hits:
            print(f"\n=== {name} 命中 {len(hits)} ===")
            for cn, acc, sup, cdata in hits:
                print(f"  {cn}")
                if sup and sup != "?":
                    print(f"       extends {sup}   [{acc_str(acc)}]")
        total += len(hits)
    print(f"\n合计 {total} 个类")


def cmd_members(apk, target, grep_pat=None):
    rx = re.compile(grep_pat, re.I) if grep_pat else None
    target_desc = "L" + target.replace(".", "/") + ";"
    for name, dex in load_dex_files(apk):
        for c_idx, acc, super_idx, cdata_off in dex.iter_class_defs():
            if dex.type_str(c_idx) != target_desc:
                continue
            print(f"\n=== {dex.class_name(c_idx)}  [{acc_str(acc)}]  in {name}")
            print(f"    extends {dex.type_display(super_idx)}")
            if not cdata_off:
                print("    (无 class_data，可能是接口/空类)")
                return
            sfl, infl, dml, vml = dex.class_members(c_idx, cdata_off)
            print(f"\n  -- 静态字段 ({len(sfl)}) --")
            for idx, a in sfl:
                c, n, t = dex.field_ref(idx)
                if rx and not rx.search(n):
                    continue
                print(f"    {t:45s} {n}  [{acc_str(a)}]")
            print(f"\n  -- 实例字段 ({len(infl)}) --")
            for idx, a in infl:
                c, n, t = dex.field_ref(idx)
                if rx and not rx.search(n):
                    continue
                print(f"    {t:45s} {n}  [{acc_str(a)}]")
            for label, lst in (("直接方法", dml), ("虚方法", vml)):
                print(f"\n  -- {label} ({len(lst)}) --")
                for idx, a, code in lst:
                    c, n, pr = dex.method_ref(idx)
                    if rx and not rx.search(n):
                        continue
                    tag = "native" if a & 0x100 else (f"code@0x{code:x}" if code else "abstract")
                    print(f"    {n}{pr}  [{acc_str(a)}] {tag}")
            return
    print(f"[!] 未找到类 {target}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    apk = sys.argv[2]
    if cmd == "classes":
        cmd_classes(apk, sys.argv[3])
    elif cmd == "members":
        gp = None
        if "--grep" in sys.argv:
            gp = sys.argv[sys.argv.index("--grep") + 1]
        cmd_members(apk, sys.argv[3], gp)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
