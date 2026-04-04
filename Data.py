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

"""CSV 数据加载模块（精灵属性 / 精灵名 / 技能名）。

对外接口与原版完全兼容，额外新增 get_maps() 懒加载单例，
避免多次重复读取 CSV 文件。
"""
from __future__ import annotations

import csv
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR   = SCRIPT_DIR / "Data"
ATTR_CSV   = DATA_DIR / "Attr.csv"
PET_CSV    = DATA_DIR / "Pet.csv"
SKILL_CSV  = DATA_DIR / "Skill.csv"


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

def _safe_int(text: str | None) -> int | None:
    if text is None:
        return None
    s = text.strip()
    try:
        return int(s, 10) if s else None
    except ValueError:
        return None


def _read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        rows: list[dict[str, str]] = []
        for row in reader:
            norm = {str(k).strip(): (v or "").strip() for k, v in row.items() if k is not None}
            if any(norm.values()):
                rows.append(norm)
        return rows


def _build_id_name_map(rows: list[dict[str, str]], *, id_field: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in rows:
        eid = _safe_int(row.get(id_field))
        name = (row.get("name") or "").strip()
        if eid is not None and name:
            out[eid] = name
    return out


# ---------------------------------------------------------------------------
# 公开：按表加载（每次都重新读文件）
# ---------------------------------------------------------------------------

def load_attr_rows()  -> list[dict[str, str]]: return _read_rows(ATTR_CSV)
def load_pet_rows()   -> list[dict[str, str]]: return _read_rows(PET_CSV)
def load_skill_rows() -> list[dict[str, str]]: return _read_rows(SKILL_CSV)

def load_attr_map()   -> dict[int, str]: return _build_id_name_map(load_attr_rows(),  id_field="attr_id")
def load_pet_map()    -> dict[int, str]: return _build_id_name_map(load_pet_rows(),   id_field="pet_id")
def load_skill_map()  -> dict[int, str]: return _build_id_name_map(load_skill_rows(), id_field="skill_id")

def load_all_maps() -> dict[str, dict[int, str]]:
    return {"attr": load_attr_map(), "pet": load_pet_map(), "skill": load_skill_map()}


# ---------------------------------------------------------------------------
# 懒加载单例（推荐在主程序中使用）
# ---------------------------------------------------------------------------

_cache: dict[str, dict[int, str]] | None = None

def get_maps() -> dict[str, dict[int, str]]:
    """首次调用时读取 CSV，后续直接返回缓存。"""
    global _cache
    if _cache is None:
        _cache = load_all_maps()
    return _cache

def invalidate_cache() -> None:
    """热重载 / 测试时调用，使下次 get_maps() 重新读取文件。"""
    global _cache
    _cache = None