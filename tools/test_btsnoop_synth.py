#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
合成 btsnoop 测试数据生成器 —— 用于自测 btsnoop_analyze.py

构造一份"已知答案"的假抓包，包含：
  - ATT MTU 协商
  - 服务发现（Read By Group Type -> 0xFFF0）
  - 特征发现（Read By Type 0x2803 -> 0xFFF1，值句柄 0x0012）
  - 3 轮带递增计数器的写帧（应在 offset 0 变化）
  - 3 次完全相同的写帧（应判定为恒定/可重放）
  - SMP Pairing Request，auth_req=0x0D（Bonding + MITM + SC）

预期结论：G1 命中（有 Bonding）、G3 为"有防重放"。

用法：python test_btsnoop_synth.py ../captures/synthetic.log
"""

import struct
import sys

MAGIC = b"btsnoop\x00"
DATALINK_H4 = 1001

CONN = 0x0040
BASE_TS = 1_600_000_000.0  # 任意基准时间（秒）


class Builder:
    def __init__(self):
        self.records = []
        self.t = BASE_TS

    def _acl(self, sent, l2cid, att_payload):
        l2 = struct.pack("<HH", len(att_payload), l2cid) + att_payload
        # LE ACL: PB=0b00 表示完整 L2CAP PDU
        hf = CONN | (0x00 << 12)
        acl = struct.pack("<HH", hf, len(l2)) + l2
        hci = b"\x02" + acl          # H4 类型字节 0x02 = ACL Data
        self.t += 0.05
        self._rec(sent, hci)

    def att_tx(self, payload):   # 手机 -> 车机
        self._acl(True, 0x0004, payload)

    def att_rx(self, payload):   # 车机 -> 手机
        self._acl(False, 0x0004, payload)

    def smp_tx(self, payload):
        self._acl(True, 0x0006, payload)

    def _rec(self, sent, hci):
        flags = 0 if sent else 1
        ts_us = int(round(self.t * 1_000_000))
        hi = ts_us >> 32
        lo = ts_us & 0xFFFFFFFF
        hdr = struct.pack(">IIIIII", len(hci), len(hci), flags, 0, hi, lo)
        self.records.append(hdr + hci)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(MAGIC)
            f.write(struct.pack(">II", 1, DATALINK_H4))
            for r in self.records:
                f.write(r)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "synthetic.log"
    b = Builder()

    # 1) MTU 协商
    b.att_tx(bytes([0x02]) + struct.pack("<H", 247))       # MTU Request
    b.att_rx(bytes([0x03]) + struct.pack("<H", 247))       # MTU Response

    # 2) 服务发现：Read By Group Type
    b.att_tx(bytes([0x10]) + struct.pack("<HH", 1, 0xFFFF) + struct.pack("<H", 0x2800))
    # Response: len=6, start=0x0010, end=0x001F, uuid=0xFFF0
    b.att_rx(
        bytes([0x11, 0x06])
        + struct.pack("<HH", 0x0010, 0x001F)
        + struct.pack("<H", 0xFFF0)
    )

    # 3) 特征发现：Read By Type (0x2803)
    b.att_tx(bytes([0x08]) + struct.pack("<HH", 0x0011, 0x001F) + struct.pack("<H", 0x2803))
    # Response: len=7, handle=0x0011, props=0x1A, value_handle=0x0012, uuid=0xFFF1
    item = struct.pack("<H", 0x0011) + bytes([0x1A]) + struct.pack("<H", 0x0012) + struct.pack("<H", 0xFFF1)
    b.att_rx(bytes([0x09, len(item)]) + item)

    # 4) 三轮带计数器的写帧（Write Request，句柄 0x0012）
    for ctr in (0x01, 0x02, 0x03):
        val = bytes([ctr]) + bytes.fromhex("11223344556677")
        b.att_tx(bytes([0x12]) + struct.pack("<H", 0x0012) + val)
        b.att_rx(bytes([0x13]))                       # Write Response
        # 车机回通知（句柄 0x0012）
        b.att_rx(bytes([0x1B]) + struct.pack("<H", 0x0012) + bytes.fromhex("9000"))

    # 5) 三次完全相同的写帧（Write Command 0x52，句柄 0x0015）
    for _ in range(3):
        b.att_tx(bytes([0x52]) + struct.pack("<H", 0x0015) + bytes.fromhex("aabbccdd"))

    # 6) SMP 配对（auth_req=0x0D -> Bonding + MITM + SC）
    b.smp_tx(bytes([0x01, 0x03, 0x00, 0x0D, 0x10, 0x07, 0x07]))

    b.write(out)
    print(f"[OK] 已生成合成抓包：{out}（{len(b.records)} 条 HCI 记录）")


if __name__ == "__main__":
    main()
