#!/usr/bin/env python3
# Copyright (C) 2026 Yuzeis
#
# This file is part of Rock Kingdom Battle Protocol Parser (RKBPP).
# Licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).
# You must retain the author attribution, this notice, the LICENSE file,
# and the NOTICE file in redistributions and derivative works.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE
# file for more details.

"""核心分析器：RkbppAnalyzer。

BE21帧 → AES解密 → proto解析 → opcode dispatch → CSV/listener 输出。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scapy.all import PcapWriter, TCP  # type: ignore

import rkbpp_proto as proto
from rkbpp_io import CsvSink, SessionLogger, now_text
from rkbpp_network import (Be21Packet, FlowState, FlowState,
                           decrypt_4013_body, flow_key_from_packet,
                           packet_has_target_port, printable_ascii, write_key_file)


class RkbppAnalyzer:
    def __init__(self, *, port: int, logger: SessionLogger, writer: PcapWriter | None,
                 key_file: Path, csv_sink: CsvSink | None,
                 preset_key: bytes | None, stop_after_key: bool,
                 analysis_listener: Any | None = None) -> None:
        self.port = port; self.logger = logger; self.writer = writer
        self.key_file = key_file; self.csv_sink = csv_sink
        self.preset_key = preset_key; self.stop_after_key = stop_after_key
        self.analysis_listener = analysis_listener
        self.should_stop = False; self.packet_count = 0
        self.key_hits = 0; self.decoded_rows = 0
        self.flows: dict[tuple[str, int, str, int], FlowState] = {}

    # ------------------------------------------------------------------
    # 包入口
    # ------------------------------------------------------------------

    def process_packet(self, packet, frame_no: int | None = None) -> None:
        if not packet_has_target_port(packet, self.port): return
        self.packet_count += 1
        if self.writer: self.writer.write(packet)
        if not packet.haslayer(TCP): return
        payload = bytes(packet[TCP].payload)
        if not payload: return
        fi = flow_key_from_packet(packet, self.port)
        if fi is None: return
        client_ip, direction, client_port, server_ip, server_port, flow_text = fi
        fk = (client_ip, client_port, server_ip, server_port)
        flow = self.flows.get(fk)
        if flow is None:
            flow = FlowState(flow_id=flow_text, client_ip=client_ip, client_port=client_port,
                             server_ip=server_ip, server_port=server_port, key=self.preset_key)
            self.flows[fk] = flow
            self.logger.log(f"[flow] new flow={flow.flow_id}")
            if self.preset_key:
                write_key_file(self.key_file, self.preset_key, flow.flow_id)
                self.logger.log(f"[key] preset key active flow={flow.flow_id} key_hex={self.preset_key.hex()} "
                                f"key_ascii={printable_ascii(self.preset_key) or '<non-ascii>'}")
        for be21 in flow.direction_state(direction).feed(int(packet[TCP].seq), payload):
            self._handle_be21(flow, be21, packet, frame_no)

    def _handle_be21(self, flow: FlowState, be21: Be21Packet, packet, frame_no: int | None) -> None:
        if be21.cmd == 0x1002 and len(be21.header_extra) >= 18:
            key = be21.header_extra[2:18]; dedupe = (be21.seq, key.hex())
            if dedupe not in flow.seen_acks:
                flow.seen_acks.add(dedupe); flow.key = key; self.key_hits += 1
                write_key_file(self.key_file, key, flow.flow_id)
                self.logger.log(f"[ack_0x1002] flow={flow.flow_id} dir={be21.direction} seq={be21.seq} "
                                f"key_hex={key.hex()} key_ascii={printable_ascii(key) or '<non-ascii>'}")
                if self.stop_after_key: self.should_stop = True
        if self.csv_sink is not None or self.analysis_listener is not None:
            ri = self.decoded_rows
            row, parsed_info = self._decode_be21(flow, be21, packet, frame_no)
            if self.analysis_listener and parsed_info: self.analysis_listener.handle(ri, row, parsed_info)
            if self.csv_sink: self.csv_sink.write_row(row)
            self.decoded_rows += 1

    # ------------------------------------------------------------------
    # 解密 + 解析
    # ------------------------------------------------------------------

    def _decode_be21(self, flow: FlowState, be21: Be21Packet, packet, frame_no: int | None
                     ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        row: dict[str, Any] = {
            "captured_at": now_text(), "frame_no": frame_no or "",
            "packet_time": f"{float(packet.time):.6f}" if hasattr(packet, "time") else "",
            "flow_id": flow.flow_id, "client_ip": flow.client_ip, "client_port": flow.client_port,
            "server_ip": flow.server_ip, "server_port": flow.server_port,
            "direction": be21.direction, "stream_offset": be21.stream_offset,
            "seq": be21.seq, "cmd": be21.cmd, "cmd_hex": f"0x{be21.cmd:04X}",
            "hdr_len": be21.hdr_len, "body_len": be21.body_len,
            "header_extra_hex": be21.header_extra.hex(), "body_hex": be21.body.hex(),
            "key_hex": flow.key.hex() if flow.key else "", "key_ascii": printable_ascii(flow.key) if flow.key else "",
            **{k: "" for k in ("decrypt_status","iv_hex","cipher_hex","decrypted_body_hex",
                                "protocol_direction","opcode","opcode_hex","subtype","magic_hex",
                                "req_seq","payload_len","root_clean","inner_message_id",
                                "summary_kind","summary_text","summary_json","record_json","root_json")},
        }
        if be21.cmd != 0x4013: row["decrypt_status"] = "not_4013"; return row, None
        if flow.key is None:   row["decrypt_status"] = "no_key";   return row, None
        try:
            iv, plain = decrypt_4013_body(flow.key, be21.body)
            row.update({"decrypt_status": "ok", "iv_hex": iv.hex(),
                        "cipher_hex": be21.body[16:].hex(), "decrypted_body_hex": plain.hex()})
            pkt_dict = {"cmd": 0x4013, "cmd_hex": "0x4013", "direction": be21.direction,
                        "seq": be21.seq, "body_len": be21.body_len,
                        "header_extra_hex": be21.header_extra.hex(), "first_frame": frame_no,
                        "first_time": float(packet.time) if hasattr(packet, "time") else None,
                        "decrypted_body_hex": plain.hex()}
            record = proto.parse_record(pkt_dict)
            if record is None: row["decrypt_status"] = "ok_unparsed"; return row, None
            row.update({"protocol_direction": record.get("direction",""), "opcode": record.get("opcode",""),
                        "opcode_hex": record.get("opcode_hex",""), "subtype": record.get("subtype",""),
                        "magic_hex": record.get("magic_hex",""), "req_seq": record.get("req_seq",""),
                        "payload_len": record.get("payload_len",""),
                        "root_clean": record.get("root",{}).get("clean","")})
            inner = None
            if record.get("opcode") == 0x0414:
                inner = proto.extract_inner_message(record["root"])
                if inner: row["inner_message_id"] = inner.get("message_id","")
            sk, so = self._summarize(record, inner)
            row.update({"summary_kind": sk, "summary_text": self._fmt_text(sk, so),
                        "summary_json": json.dumps(so, ensure_ascii=False),
                        "record_json": json.dumps(dict(record), ensure_ascii=False),
                        "root_json": json.dumps(record.get("root"), ensure_ascii=False)})
            return row, {"record": record, "inner": inner, "summary_kind": sk, "summary_obj": so}
        except Exception as exc:
            row["decrypt_status"] = f"error:{exc}"; return row, None

    # ------------------------------------------------------------------
    # opcode dispatch: summarize
    # ------------------------------------------------------------------

    def _summarize(self, record: dict[str, Any], inner: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        op = int(record.get("opcode", 0))
        if op == 0x0102: return "roster_init",          {"metadata": proto.extract_0102_metadata(record), "creatures": proto.extract_0102_creatures(record)}
        if op in {0x1316, 0x131A}: return "state_update", {"wrappers": proto.extract_state_wrappers_from_record(record)}
        if op == 0x0414:
            mid = inner.get("message_id") if inner else None
            _D = {390: ("inner390_pair",   lambda: proto.parse_inner390_detail(inner["fields"])),
                  200: ("inner200_commit", lambda: proto.parse_inner200_detail(inner["fields"])),
                  51:  ("inner51_event",   lambda: proto.parse_inner51_detail(inner["fields"])),
                  1:   ("inner1_effect",   lambda: proto.parse_inner1_detail(inner["fields"]))}
            if mid in _D: k, fn = _D[mid]; return k, {"detail": fn()}
            return "inner_unknown", {"message_id": mid}
        if op == 0x130B: return "client_skill_select",  {"detail": proto.extract_130b_skill_select(record)}
        if op == 0x1322: return "server_skill_declare", {"detail": proto.extract_1322_skill_declare(record)}
        if op == 0x1324: return "action_resolve",       {"detail": proto.extract_1324_action(record)}
        if op == 0x13F4: return "special_refresh",      {"detail": proto.extract_13f4_refresh(record)}
        if op == 0x130C: return "server_action_ack",    {"detail": proto.extract_130c_result(record)}
        if op == 0x1314: return "turn_control",         {"detail": proto.extract_1314_phase(record)}
        if op == 0x01A9: return "client_action",        {"candidate_ids": self._extract_01a9(record)}
        if op == 0x0220: return "snapshot_handle",      {"handle": proto.extract_0220_handle(record)}
        return "opcode_only", {"opcode_hex": record.get("opcode_hex")}

    def _extract_01a9(self, record: dict[str, Any]) -> dict[str, Any]:
        fg = proto.field_groups; cv = proto.collect_varints; pf = proto.pick_first
        out: dict[str, Any] = {"candidate_ids": []}
        for oe in fg(record["root"]).get(4, []):
            outer = oe.get("sub")
            if outer is None: continue
            pe = next((e for e in fg(outer).get(2, []) if e.get("sub")), None)
            if pe is None: continue
            payload = pe["sub"]; ids: list[int] = []
            for fn in (1, 2):
                item = next((e for e in fg(payload).get(fn, []) if e.get("sub")), None)
                if item:
                    for f in (1,2,3): ids.extend(cv(item["sub"], f))
            out.update({"candidate_ids": [int(v) for v in ids], "actor_token": pf(cv(outer, 1)),
                        "raw_kind": pf(cv(outer, 4))})
            if ids: out["primary_id"] = int(ids[0])
            break
        return out

    # ------------------------------------------------------------------
    # opcode dispatch: format text
    # ------------------------------------------------------------------

    def _fmt_text(self, sk: str, so: dict[str, Any]) -> str:
        d = so.get("detail") or {}
        if sk == "roster_init":
            names = [it.get("name") for it in (so.get("creatures") or []) if it.get("name")]
            nick  = ((so.get("metadata") or {}).get("player") or {}).get("nickname")
            parts = ([f"player={nick}"] if nick else []) + (["roster=" + "/".join(str(n) for n in names[:6])] if names else [])
            return " | ".join(parts)
        if sk == "state_update":
            ws = so.get("wrappers") or []
            parts = [f"{it.get('name') or it.get('pet_id')}:{it.get('current_hp')}/{it.get('battle_max_hp')}"
                     if it.get("current_hp") is not None else str(it.get("name") or it.get("pet_id"))
                     for it in ws[:4]]
            return f"wrappers={len(ws)}" + (f" | {'; '.join(parts)}" if parts else "")
        if sk in {"client_skill_select", "server_skill_declare"}:
            if d.get("action_name"):
                parts = [f"action={d.get('action_name')}"]
                if d.get("command_slot") is not None: parts.append(f"slot={d.get('command_slot')}")
                if d.get("payload_kind") is not None: parts.append(f"kind={d.get('payload_kind')}")
                return " | ".join(parts)
            return " | ".join(filter(None, [f"skill={d.get('skill_name') or '?'}", f"skill_id={d.get('skill_id')}",
                                            f"x100={d.get('skill_id_x100')}",
                                            f"slot={d.get('command_slot')}" if d.get("command_slot") is not None else None]))
        if sk == "action_resolve":
            ps = d.get("primary_skill") or {}; dm = d.get("damage_event") or {}; en = d.get("energy_event") or {}
            parts = []
            if ps.get("skill_id"): parts.append(f"skill={ps.get('skill_name') or '?'}({ps.get('skill_id')})")
            if en.get("energy_delta") is not None or en.get("energy_after") is not None:
                parts.append(f"energy={en.get('energy_delta')}->{en.get('energy_after')}")
            if dm.get("damage"): parts.append(f"damage={dm.get('damage')}")
            if dm.get("target_hp_after"): parts.append(f"target_hp={dm.get('target_hp_after')}")
            if d.get("effect_ids"): parts.append("effects=" + "/".join(str(x) for x in d["effect_ids"][:6]))
            if d.get("has_defeat"): parts.append("defeat=1")
            return " | ".join(parts) if parts else "0x1324"
        if sk == "special_refresh":
            parts = ([f"action={d.get('action_name')}"] if d.get("action_name") else [])
            if d.get("energy_delta") is not None or d.get("energy_after") is not None:
                parts.append(f"energy={d.get('energy_delta')}->{d.get('energy_after')}")
            if d.get("skill_options"):
                parts.append("skills=" + "; ".join(f"{it.get('slot')}:{it.get('skill_name') or '?'}({it.get('skill_id')})"
                                                    for it in d["skill_options"][:6]))
            return " | ".join(parts) if parts else "0x13F4"
        if sk == "server_action_ack":
            parts = ([f"action={d.get('action_name')}"] if d.get("action_name") else
                     [f"skill_id={d.get('skill_id')}"] if d.get("skill_id") is not None else [])
            if d.get("current_hp")  is not None: parts.append(f"hp={d.get('current_hp')}")
            if d.get("energy_after") is not None: parts.append(f"energy={d.get('energy_after')}")
            if d.get("state_wrappers"): parts.append(f"wrappers={len(d['state_wrappers'])}")
            return " | ".join(parts) if parts else "0x130C"
        if sk == "turn_control":     return f"phase_code={d.get('phase_code')}"
        if sk == "inner390_pair":
            f_ = (d.get("friendly") or {}); e_ = (d.get("enemy") or {})
            return f"pair={f_.get('name') or f_.get('pet_id')} vs {e_.get('name') or e_.get('pet_id')}"
        if sk == "inner200_commit":
            c = d.get("commit") or {}
            return f"flag={c.get('flag')} | code={c.get('code')} | event_time_ms={c.get('event_time_ms')}"
        if sk == "inner51_event":    return f"kind={d.get('kind')} | value2={d.get('value2')} | value3={d.get('value3')}"
        if sk == "inner1_effect":
            h = d.get("header") or {}; e = d.get("effect") or {}
            return f"actor={h.get('actor_token')} | effect_id={e.get('effect_id')} | code={e.get('code')} | amount={e.get('amount')}"
        if sk == "client_action":
            info = so.get("candidate_ids") or {}; ids = info.get("candidate_ids") or []
            return f"primary={info.get('primary_id')} | raw_kind={info.get('raw_kind')} | actor={info.get('actor_token')} | ids={'/'.join(str(x) for x in ids[:6])}"
        if sk == "snapshot_handle":  return f"handle={so.get('handle')}"
        return so.get("opcode_hex","") or sk