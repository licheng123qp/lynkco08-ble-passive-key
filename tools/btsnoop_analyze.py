#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
btsnoop 蓝牙抓包解析器 —— 领克 08 蓝牙钥匙协议侦察专用

用途：不安装 Wireshark，直接从 Android 的 btsnoop_hci.log 里还原
      1) GATT 服务/特征 UUID 完整清单
      2) 每一条 Write / Notify 的原始载荷（十六进制）
      3) SMP 配对流程是否存在  -> 判定闸门 G1
      4) 重复操作之间载荷的差异字节  -> 判定闸门 G3（防重放）

用法：
    python btsnoop_analyze.py captures/btsnoop_hci.log
    python btsnoop_analyze.py captures/btsnoop_hci.log -o report.md --json out.json

仅依赖 Python 3.8+ 标准库。
"""

import argparse
import json
import struct
import sys
from collections import OrderedDict, defaultdict

# ---------------------------------------------------------------- 常量表

BTSNOOP_MAGIC = b"btsnoop\x00"

L2CAP_CID_ATT = 0x0004
L2CAP_CID_LE_SIG = 0x0005
L2CAP_CID_SMP = 0x0006

ATT_NAMES = {
    0x01: "Error Response",
    0x02: "MTU Request",
    0x03: "MTU Response",
    0x04: "Find Information Request",
    0x05: "Find Information Response",
    0x06: "Find By Type Value Request",
    0x07: "Find By Type Value Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x0C: "Read Blob Request",
    0x0D: "Read Blob Response",
    0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response",
    0x10: "Read By Group Type Request",
    0x11: "Read By Group Type Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x16: "Prepare Write Request",
    0x17: "Prepare Write Response",
    0x18: "Execute Write Request",
    0x19: "Execute Write Response",
    0x1B: "Handle Value Notification",
    0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
    0x1F: "Signed Write Command",
    0x52: "Write Command",
}

# 有方向语义的写操作
ATT_WRITE_OPS = {0x12, 0x52, 0x16, 0x18, 0x1F}
ATT_READ_RESP_OPS = {0x09, 0x0B, 0x0D, 0x11, 0x05, 0x07, 0x0F}
ATT_NOTIFY_OPS = {0x1B, 0x1D}

SMP_NAMES = {
    0x01: "Pairing Request",
    0x02: "Pairing Response",
    0x03: "Pairing Confirm",
    0x04: "Pairing Random",
    0x05: "Pairing Failed",
    0x06: "Encryption Information",
    0x07: "Master Identification",
    0x08: "Identity Information",
    0x09: "Identity Address Information",
    0x0A: "Signing Information",
    0x0B: "Pairing Public Key",
    0x0C: "Pairing DHKey Check",
    0x0D: "Pairing Keypress Notification",
}

# 标准 GATT 描述符 / 特征声明 UUID
UUID_NAMES = {
    0x2800: "Primary Service",
    0x2801: "Secondary Service",
    0x2802: "Include",
    0x2803: "Characteristic",
    0x2900: "Characteristic Extended Properties",
    0x2901: "Characteristic User Description",
    0x2902: "Client Characteristic Configuration (CCCD)",
    0x2903: "Server Characteristic Configuration",
    0x2904: "Characteristic Presentation Format",
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A05: "Service Changed",
}


def uuid_str(val: int) -> str:
    """把 16bit UUID 展开成标准蓝牙基础 UUID 形式。"""
    if val in UUID_NAMES:
        return f"0x{val:04X} ({UUID_NAMES[val]})"
    return f"0x{val:04X} -> 0000{val:04x}-0000-1000-8000-00805f9b34fb"


def uuid_bytes_str(b: bytes) -> str:
    if len(b) == 2:
        # 只返回规范形式，名字由调用方按需查表；否则会污染 type_uuid 的解析
        return f"0x{struct.unpack('<H', b)[0]:04X}"
    if len(b) == 16:
        # 蓝牙 UUID 是小端存储
        return (
            f"{b[3]:02x}{b[2]:02x}{b[1]:02x}{b[0]:02x}-"
            f"{b[5]:02x}{b[4]:02x}-{b[7]:02x}{b[6]:02x}-"
            f"{b[8]:02x}{b[9]:02x}-"
            f"{b[10]:02x}{b[11]:02x}{b[12]:02x}{b[13]:02x}{b[14]:02x}{b[15]:02x}"
        )
    return b.hex()


def uuid16_of(b: bytes):
    if len(b) == 2:
        return struct.unpack("<H", b)[0]
    return None


# ---------------------------------------------------------------- 容器解析


def parse_btsnoop(path):
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(BTSNOOP_MAGIC):
        raise ValueError(
            "不是 btsnoop 文件（文件头不匹配）。"
            "请确认抓到的是 btsnoop_hci.log，而不是 BT_HCI 的 .cfa/.pcap。"
        )
    version, datalink = struct.unpack_from(">II", data, 8)
    off = 16
    records = []
    while off + 24 <= len(data):
        orig_len, incl_len, flags, drops, ts_hi, ts_lo = struct.unpack_from(
            ">IIIIII", data, off
        )
        off += 24
        pkt = data[off : off + incl_len]
        off += incl_len
        if len(pkt) < incl_len:
            break
        ts = ((ts_hi << 32) | ts_lo) / 1e6
        records.append(
            {"ts": ts, "sent": (flags & 1) == 0, "drops": drops, "data": pkt}
        )
    return version, datalink, records


def _h4_score(records):
    """判断包里是否带 H4 类型字节。返回 (ok, bad)。"""
    ok = bad = 0
    for r in records[:400]:
        d = r["data"]
        if len(d) < 4:
            continue
        t = d[0]
        if t == 0x02 and len(d) >= 5:
            dlen = struct.unpack_from("<H", d, 3)[0]
            if len(d) - 5 == dlen:
                ok += 1
            else:
                bad += 1
        elif t == 0x04 and len(d) >= 3:
            plen = d[2]
            if len(d) - 3 == plen:
                ok += 1
            else:
                bad += 1
        elif t == 0x01 and len(d) >= 4:
            plen = d[3]
            if len(d) - 4 == plen:
                ok += 1
            else:
                bad += 1
    return ok, bad


def _raw_acl_score(records):
    """判断是否为无类型字节的裸 ACL（datalink 1002）。"""
    ok = bad = 0
    for r in records[:400]:
        d = r["data"]
        if len(d) < 4:
            continue
        dlen = struct.unpack_from("<H", d, 2)[0]
        if len(d) - 4 == dlen:
            ok += 1
        else:
            bad += 1
    return ok, bad


def iter_acl(records, datalink):
    """产出 (ts, sent, handle, pb, payload)。"""
    h4_ok, h4_bad = _h4_score(records)
    raw_ok, raw_bad = _raw_acl_score(records)

    use_h4 = h4_ok > h4_bad
    if not use_h4:
        use_raw = raw_ok > raw_bad
        if not use_raw:
            # 两种都不完美：按 datalink 猜。1001/1002 都以 H4 更常见
            use_h4 = True

    layout = "H4(带类型字节)" if use_h4 else "裸ACL(无类型字节)"
    out = []
    for r in records:
        d = r["data"]
        if use_h4:
            if not d or d[0] != 0x02 or len(d) < 5:
                continue
            hf = struct.unpack_from("<H", d, 1)[0]
            payload = d[5:]
        else:
            if len(d) < 4:
                continue
            hf = struct.unpack_from("<H", d, 0)[0]
            payload = d[4:]
        handle = hf & 0x0FFF
        pb = (hf >> 12) & 0x03
        out.append(
            {"ts": r["ts"], "sent": r["sent"], "handle": handle, "pb": pb, "d": payload}
        )
    return out, layout


def reassemble_l2cap(acl):
    """按连接句柄 + PB 标志重组 L2CAP PDU。"""
    buf = defaultdict(bytearray)
    pdus = []
    for p in acl:
        h = p["handle"]
        pb = p["pb"]
        if pb in (0x00, 0x02):
            if buf[h]:
                # 上一段没等齐，丢弃并记录
                pass
            buf[h] = bytearray(p["d"])
        else:
            buf[h] += p["d"]
        raw = buf[h]
        # 尽量从缓冲区里切出完整 PDU（可能一个 ACL 里有多个）
        while len(raw) >= 4:
            l2len = struct.unpack_from("<H", raw, 0)[0]
            total = 4 + l2len
            if len(raw) < total:
                break
            cid = struct.unpack_from("<H", raw, 2)[0]
            pdus.append(
                {
                    "ts": p["ts"],
                    "sent": p["sent"],
                    "handle": h,
                    "cid": cid,
                    "payload": bytes(raw[4:total]),
                }
            )
            del raw[:total]
        buf[h] = raw
    return pdus


# ---------------------------------------------------------------- ATT / SMP


def parse_att(payload):
    """解析 ATT PDU，返回 dict。"""
    if not payload:
        return None
    op = payload[0]
    info = {"op": op, "name": ATT_NAMES.get(op, f"Unknown 0x{op:02X}")}
    try:
        if op == 0x12 and len(payload) >= 3:  # Write Request
            info["handle"] = struct.unpack_from("<H", payload, 1)[0]
            info["value"] = payload[3:]
        elif op == 0x52 and len(payload) >= 3:  # Write Command
            info["handle"] = struct.unpack_from("<H", payload, 1)[0]
            info["value"] = payload[3:]
        elif op == 0x1B and len(payload) >= 3:  # Notification
            info["handle"] = struct.unpack_from("<H", payload, 1)[0]
            info["value"] = payload[3:]
        elif op == 0x1D and len(payload) >= 3:  # Indication
            info["handle"] = struct.unpack_from("<H", payload, 1)[0]
            info["value"] = payload[3:]
        elif op == 0x0A and len(payload) >= 3:  # Read Request
            info["handle"] = struct.unpack_from("<H", payload, 1)[0]
        elif op == 0x0B:  # Read Response
            info["value"] = payload[1:]
        elif op in (0x10, 0x08, 0x06, 0x04):
            start, end = struct.unpack_from("<HH", payload, 1)
            u = payload[5:] if len(payload) > 5 else b""
            info["start"] = start
            info["end"] = end
            info["type_uuid"] = uuid_bytes_str(u) if u else ""
        elif op == 0x11:  # Read By Group Type Response
            items = []
            length = payload[1]
            i = 2
            while i + length <= len(payload) and length >= 4:
                s = struct.unpack_from("<H", payload, i)[0]
                e = struct.unpack_from("<H", payload, i + 2)[0]
                ub = payload[i + 4 : i + length]
                items.append({"start": s, "end": e, "uuid": uuid_bytes_str(ub),
                              "u16": uuid16_of(ub)})
                i += length
            info["items"] = items
        elif op == 0x09:  # Read By Type Response
            items = []
            length = payload[1]
            i = 2
            while i + length <= len(payload) and length >= 2:
                h = struct.unpack_from("<H", payload, i)[0]
                vb = payload[i + 2 : i + length]
                items.append({"handle": h, "value": vb})
                i += length
            info["items"] = items
        elif op == 0x05:  # Find Information Response
            items = []
            fmt = payload[1]
            i = 2
            step = 4 if fmt == 1 else 18
            while i + step <= len(payload):
                h = struct.unpack_from("<H", payload, i)[0]
                items.append({"handle": h, "uuid": uuid_bytes_str(payload[i + 2 : i + step])})
                i += step
            info["items"] = items
        elif op == 0x02:  # MTU Request
            info["mtu"] = struct.unpack_from("<H", payload, 1)[0]
        elif op == 0x03:
            info["mtu"] = struct.unpack_from("<H", payload, 1)[0]
        elif op == 0x01 and len(payload) >= 5:  # Error Response
            info["req_op"] = payload[1]
            info["handle"] = struct.unpack_from("<H", payload, 2)[0]
            info["code"] = payload[4]
    except struct.error:
        pass
    return info


def parse_smp(payload):
    if not payload:
        return None
    op = payload[0]
    info = {"op": op, "name": SMP_NAMES.get(op, f"Unknown 0x{op:02X}")}
    if op in (0x01, 0x02) and len(payload) >= 7:
        info["io_cap"] = payload[1]
        info["oob"] = payload[2]
        info["auth_req"] = payload[3]
        info["max_key_size"] = payload[4]
        info["init_key_dist"] = payload[5]
        info["resp_key_dist"] = payload[6]
        # authreq bit: 0x08 = Bonding, 0x04 = MITM, 0x01 = SC
        info["bonding"] = bool(payload[3] & 0x08)
        info["mitm"] = bool(payload[3] & 0x04)
        info["secure_connections"] = bool(payload[3] & 0x01)
    return info


# ---------------------------------------------------------------- 主分析


class Analyzer:
    def __init__(self, path):
        self.path = path
        self.version, self.datalink, self.records = parse_btsnoop(path)
        acl, self.layout = iter_acl(self.records, self.datalink)
        self.pdus = reassemble_l2cap(acl)
        self.att_log = []          # 按时间排序的 ATT 事件
        self.smp_log = []
        self.services = OrderedDict()   # start_handle -> dict
        self.char_uuids = {}            # value_handle -> uuid 显示名
        self.decl_handles = {}          # decl handle -> uuid
        self.cccd = set()
        self.mtu = None
        self.discovery_seen = False
        self._run()

    def _run(self):
        self._pending = {}   # conn -> {"op": int, "type16": int|None}
        for pdu in self.pdus:
            if pdu["cid"] == L2CAP_CID_ATT:
                a = parse_att(pdu["payload"])
                if not a:
                    continue
                a.update(
                    {"ts": pdu["ts"], "sent": pdu["sent"], "conn": pdu["handle"]}
                )
                self.att_log.append(a)
                self._ingest(a)
            elif pdu["cid"] == L2CAP_CID_SMP:
                s = parse_smp(pdu["payload"])
                if s:
                    s.update(
                        {"ts": pdu["ts"], "sent": pdu["sent"], "raw": pdu["payload"].hex()}
                    )
                    self.smp_log.append(s)

    def _ingest(self, a):
        op = a["op"]
        conn = a["conn"]

        # 记录"请求"，供后续响应配对解读
        if op in (0x10, 0x08, 0x06, 0x04):
            u = None
            tu = a.get("type_uuid", "")
            if tu.startswith("0x"):
                try:
                    u = int(tu[2:6], 16)
                except ValueError:
                    u = None
            self._pending[conn] = {"op": op, "type16": u}
            if op == 0x10:
                self.discovery_seen = True
            return

        if op == 0x03:
            self.mtu = a.get("mtu")
            return

        pend = self._pending.get(conn)

        if op == 0x11:  # Read By Group Type Response -> 服务声明
            is_service = pend is None or pend.get("type16") in (None, 0x2800, 0x2801)
            if not is_service:
                return
            for it in a.get("items", []):
                key = it["start"]
                if key not in self.services:
                    self.services[key] = {
                        "start": it["start"],
                        "end": it["end"],
                        "uuid": it["uuid"],
                        "uuid16": it.get("u16"),
                        "chars": [],
                    }
            return

        if op == 0x09:  # Read By Type Response
            # 只有请求的是 0x2803（特征声明）时才按特征解析
            if pend is None or pend.get("type16") != 0x2803:
                return
            for it in a.get("items", []):
                vb = it["value"]
                h = it["handle"]
                if len(vb) not in (5, 19):
                    continue
                props = vb[0]
                val_h = struct.unpack_from("<H", vb, 1)[0]
                u = uuid_bytes_str(vb[3:])
                self.decl_handles[h] = u
                self.char_uuids[val_h] = u
                for s in reversed(list(self.services.values())):
                    if s["start"] <= h <= s["end"]:
                        s["chars"].append(
                            {"decl": h, "value_handle": val_h,
                             "props": props, "uuid": u}
                        )
                        break
            return

    # -------- 派生结论

    def gatt_table(self):
        rows = []
        for s in self.services.values():
            rows.append(
                {
                    "service": s["uuid"],
                    "range": f"0x{s['start']:04X}-0x{s['end']:04X}",
                    "chars": s["chars"],
                }
            )
        return rows

    def write_events(self):
        """所有主机 -> 车机 的写操作。"""
        out = []
        for a in self.att_log:
            if a["op"] in ATT_WRITE_OPS and "value" in a:
                out.append(
                    {
                        "ts": a["ts"],
                        "handle": a["handle"],
                        "uuid": self.char_uuids.get(a["handle"]),
                        "op": a["name"],
                        "hex": a["value"].hex(),
                    }
                )
        return out

    def notify_events(self):
        out = []
        for a in self.att_log:
            if a["op"] in ATT_NOTIFY_OPS and "value" in a:
                out.append(
                    {
                        "ts": a["ts"],
                        "handle": a["handle"],
                        "uuid": self.char_uuids.get(a["handle"]),
                        "op": a["name"],
                        "hex": a["value"].hex(),
                    }
                )
        return out

    def diff_analysis(self):
        """按句柄把多次写的载荷对齐比较，找出变化的字节位置。

        全部相同  -> 静态帧，可能可重放（G3 弱）
        某些字节变 -> 很可能是计数器 / nonce / MAC（G3 强）
        长度变化   -> 变长编码，通常含计数器
        """
        by_handle = defaultdict(list)
        for w in self.write_events():
            by_handle[w["handle"]].append(w)

        results = []
        for h, evts in by_handle.items():
            if len(evts) < 2:
                continue
            blobs = [bytes.fromhex(e["hex"]) for e in evts]
            lens = {len(b) for b in blobs}
            same = len(set(blobs)) == 1
            varying = []
            if len(lens) == 1:
                n = len(blobs[0])
                for i in range(n):
                    vals = {b[i] for b in blobs}
                    if len(vals) > 1:
                        varying.append(
                            {
                                "offset": i,
                                "values": [f"{v:02x}" for v in sorted(vals)][:8],
                            }
                        )
            results.append(
                {
                    "handle": h,
                    "uuid": evts[0]["uuid"],
                    "count": len(evts),
                    "len": sorted(lens),
                    "identical": same,
                    "varying_offsets": varying,
                    "samples": [e["hex"] for e in evts[:6]],
                }
            )
        results.sort(key=lambda x: -x["count"])
        return results

    def verdicts(self):
        v = {}
        # G1: 是否 BLE 配对绑定
        smp_ops = [s["op"] for s in self.smp_log]
        pairing = [s for s in self.smp_log if s["op"] in (0x01, 0x02)]
        v["G1_smp_present"] = bool(self.smp_log)
        v["G1_pairing_bonding"] = any(
            s.get("bonding") for s in pairing
        )
        v["G1_detail"] = (
            "无 SMP 报文 —— 协议不依赖 BLE 配对绑定，G1 通过"
            if not self.smp_log
            else f"检测到 SMP 流程，opcode={[hex(o) for o in smp_ops]}；"
            + (
                "且发起方请求 Bonding（auth_req bit3）—— G1 极可能命中，新 APP 无法继承 bond"
                if any(s.get("bonding") for s in pairing)
                else "未声明 Bonding 位，但仍需人工确认是否加密链路"
            )
        )

        # G3: 防重放
        diffs = self.diff_analysis()
        static_frames = [d for d in diffs if d["identical"]]
        dynamic_frames = [d for d in diffs if not d["identical"]]
        v["G3_static_handles"] = [
            {"handle": d["handle"], "uuid": d["uuid"], "count": d["count"]}
            for d in static_frames
        ]
        v["G3_dynamic_handles"] = [
            {
                "handle": d["handle"],
                "uuid": d["uuid"],
                "count": d["count"],
                "varying_offsets": d["varying_offsets"],
            }
            for d in dynamic_frames
        ]
        if dynamic_frames:
            v["G3_detail"] = (
                f"{len(dynamic_frames)} 个特征在重复操作间载荷发生变化"
                "（见 varying_offsets），存在计数器/nonce 机制，不能纯重放"
            )
        elif static_frames:
            v["G3_detail"] = (
                "多次写操作载荷完全相同 —— 疑似无防重放，可先试重放验证"
            )
        else:
            v["G3_detail"] = "写操作次数不足，无法判定（建议重复采集 3 轮以上）"
        return v

    def report(self):
        lines = []
        A = lines.append
        A("# 蓝牙钥匙协议侦察报告\n")
        A(f"- 来源文件：`{self.path}`")
        A(f"- btsnoop 版本：{self.version}，datalink type：{self.datalink}")
        A(f"- ACL 解析布局：{self.layout}")
        A(f"- 原始记录数：{len(self.records)}，L2CAP PDU：{len(self.pdus)}")
        A(f"- ATT 事件：{len(self.att_log)}，SMP 事件：{len(self.smp_log)}")
        if self.records:
            span = self.records[-1]["ts"] - self.records[0]["ts"]
            A(f"- 抓包时长：{span:.1f} 秒")
        A("")

        v = self.verdicts()
        A("## 闸门判定\n")
        A(f"**G1（BLE 配对绑定）**：{'❌ 命中' if v['G1_pairing_bonding'] else '✅ 通过'}")
        A(f"> {v['G1_detail']}\n")
        A("**G3（防重放）**：见下节写帧差异分析")
        A(f"> {v['G3_detail']}\n")
        A("> G2（密钥存储）与 G4（车端证书链）需静态逆向 APK 才能判定，抓包无法回答。\n")

        A("## GATT 服务与特征清单\n")
        if not self.services:
            A("> 未发现服务发现流程（0x10/0x11）。可能本次抓包未包含服务发现阶段，")
            A("> 或设备使用了缓存服务表。建议断开重连后重新采集。\n")
        else:
            A("| 服务 UUID | 句柄范围 | 特征（值句柄 / UUID / 属性） |")
            A("|---|---|---|")
            for s in self.gatt_table():
                chars = "<br>".join(
                    f"0x{c['value_handle']:04X} `{c['uuid']}` (props=0x{c['props']:02X})"
                    for c in s["chars"]
                ) or "—"
                A(f"| `{s['service']}` | {s['range']} | {chars} |")
            A("")

        A("## 写帧（手机 → 车机）\n")
        ws = self.write_events()
        if not ws:
            A("> 无写操作。可能未触发解锁动作，或本次抓包只含连接阶段。\n")
        else:
            A("| 时间(s) | 句柄 | 特征 UUID | 操作 | 载荷(hex) |")
            A("|---|---|---|---|---|")
            t0 = self.records[0]["ts"] if self.records else 0
            for w in ws:
                A(
                    f"| {w['ts']-t0:.3f} | 0x{w['handle']:04X} | "
                    f"`{w['uuid'] or '?'}` | {w['op']} | `{w['hex']}` |"
                )
            A("")

        A("## 通知帧（车机 → 手机）\n")
        ns = self.notify_events()
        if not ns:
            A("> 无通知帧。\n")
        else:
            A("| 时间(s) | 句柄 | 特征 UUID | 操作 | 载荷(hex) |")
            A("|---|---|---|---|---|")
            t0 = self.records[0]["ts"] if self.records else 0
            for n in ns[:80]:
                A(
                    f"| {n['ts']-t0:.3f} | 0x{n['handle']:04X} | "
                    f"`{n['uuid'] or '?'}` | {n['op']} | `{n['hex']}` |"
                )
            if len(ns) > 80:
                A(f"\n> 仅显示前 80 条，共 {len(ns)} 条。\n")
            A("")

        A("## 写帧差异分析（G3 防重放判定）\n")
        diffs = self.diff_analysis()
        if not diffs:
            A("> 同一句柄写操作少于 2 次，无法比较。请把「解锁→上锁→解锁」重复 3 轮。\n")
        for d in diffs:
            tag = "🔴 载荷恒定（可重放嫌疑）" if d["identical"] else "🟢 载荷变化（有防重放）"
            A(f"### 句柄 0x{d['handle']:04X} — {tag}")
            A(f"- 特征 UUID：`{d['uuid'] or '未知'}`")
            A(f"- 出现次数：{d['count']}，长度：{d['len']}")
            if d["identical"]:
                A(f"- 恒定载荷：`{d['samples'][0]}`")
            else:
                if d["varying_offsets"]:
                    A("- 变化字节位置：")
                    for o in d["varying_offsets"]:
                        A(f"  - offset {o['offset']}：取值 {', '.join(o['values'])}")
                else:
                    A("- 长度不一致，无法逐字节对齐")
                A(f"- 样本：`{'`, `'.join(d['samples'])}`")
            A("")

        A("## SMP 配对流程\n")
        if not self.smp_log:
            A("无 SMP 报文。\n")
        else:
            A("| 时间(s) | 方向 | opcode | 名称 | 详情 |")
            A("|---|---|---|---|---|")
            t0 = self.records[0]["ts"] if self.records else 0
            for s in self.smp_log:
                extra = ""
                if "bonding" in s:
                    extra = (
                        f"bonding={s['bonding']} mitm={s['mitm']} "
                        f"SC={s['secure_connections']}"
                    )
                A(
                    f"| {s['ts']-t0:.3f} | {'手机→车' if s['sent'] else '车→手机'} | "
                    f"0x{s['op']:02X} | {s['name']} | {extra} |"
                )
            A("")
        return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="btsnoop 蓝牙抓包解析器")
    ap.add_argument("path", help="btsnoop_hci.log 路径")
    ap.add_argument("-o", "--output", help="输出 Markdown 报告路径")
    ap.add_argument("--json", help="同时输出 JSON 路径")
    args = ap.parse_args()

    try:
        an = Analyzer(args.path)
    except Exception as e:
        print(f"[错误] {e}", file=sys.stderr)
        return 1

    md = an.report()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[OK] 报告已写入 {args.output}")
    else:
        print(md)

    if args.json:
        payload = {
            "source": args.path,
            "datalink": an.datalink,
            "gatt": an.gatt_table(),
            "writes": an.write_events(),
            "notifies": an.notify_events(),
            "diffs": an.diff_analysis(),
            "smp": an.smp_log,
            "verdicts": an.verdicts(),
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"[OK] JSON 已写入 {args.json}")

    v = an.verdicts()
    print("\n===== 闸门速览 =====")
    print(f"G1 配对绑定: {'命中(危险)' if v['G1_pairing_bonding'] else '通过'}")
    print(f"G3 防重放  : {v['G3_detail']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
