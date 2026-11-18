#!/usr/bin/env python3
"""Unit tests for the transactional guarantees of the state plane.

These run in-process against a throwaway SQLite file and need no network:
  * a failing write during confirm/revoke/start leaves the previous state and
    the cache untouched (all-or-nothing);
  * a cache write carrying a superseded generation is rejected (a late
    upstream answer cannot re-enter the cache after a state change);
  * confirm/revoke/expire each invalidate the cache in the same commit and
    advance the generation.
"""
from __future__ import annotations

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="dns-trial-unit-")
os.environ["DB_PATH"] = os.path.join(TMP, "app.db")
os.environ.setdefault("FIXED_DOMAIN", "service.example")

from app import common  # noqa: E402

FAILS: list[str] = []


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def state() -> tuple[dict, dict, dict | None]:
    return common.snapshot()


def main() -> int:
    common.init_db()
    common.set_control("a", "192.0.2.10", 3.0)
    common.put_cache_a("192.0.2.10", common.time.time())
    _, control0, cache0 = state()

    # -- failing write in confirm rolls everything back ---------------------
    trial = common.start_trial("198.51.100.1", 30)
    no = trial["trial_no"]
    _, control1, _ = state()
    cache_after_start = common.get_cache()
    check("U1 试切开始清空缓存并递增 generation",
          cache_after_start is None and trial["generation"] >= 1,
          f"gen={trial['generation']}")

    original_invalidate = common._invalidate_cache

    def boom(_c):
        raise RuntimeError("simulated write failure")

    common._invalidate_cache = boom
    raised = False
    try:
        common.confirm_trial(no)
    except RuntimeError:
        raised = True
    finally:
        common._invalidate_cache = original_invalidate
    tr, ctl, cache = state()
    check("U2 确认写失败抛出且不提交", raised)
    check("U3 写失败后控制与试切状态保持原样",
          ctl["ip"] == control1["ip"] and tr["status"] == "active"
          and tr["generation"] == trial["generation"],
          f"ctl={ctl['ip']} status={tr['status']} gen={tr['generation']}")

    # -- generation guard rejects a late write ------------------------------
    old_gen = tr["generation"]
    ok = common.put_cache_a("192.0.2.10", common.time.time(),
                            generation=old_gen - 1)
    check("U4 旧 generation 的回源结果被拒绝", ok is False)
    check("U5 被拒绝的结果未写入缓存", common.get_cache() is None,
          f"cache={common.get_cache()}")

    # -- confirm invalidates the cache in one commit -------------------------
    ok, why, tr2 = common.confirm_trial(no)
    ctl2 = common.get_control()
    check("U6 确认成功并切换常驻地址",
          ok and ctl2["ip"] == "198.51.100.1" and tr2["status"] == "confirmed",
          f"ok={ok} why={why} ctl={ctl2['ip']}")
    check("U7 确认与缓存失效同一次提交",
          common.get_cache() is None and tr2["generation"] > old_gen,
          f"gen={tr2['generation']}")
    ok, why, _ = common.confirm_trial(no)
    check("U8 已确认编号不能再确认", not ok, why)

    # -- revoke invalidates the cache in one commit -------------------------
    t = common.start_trial("203.0.113.1", 30)
    common.put_cache_a("203.0.113.1", common.time.time(),
                       generation=t["generation"])
    ok, why, tr3 = common.revoke_trial(t["trial_no"])
    check("U9 撤销成功、恢复原地址并清空缓存",
          ok and common.get_control()["ip"] == "198.51.100.1"
          and common.get_cache() is None
          and tr3["generation"] > t["generation"],
          f"ok={ok} why={why}")

    # -- expiry is a real transition and invalidates the cache --------------
    t = common.start_trial("203.0.113.2", 10)
    deadline = t["deadline"]
    common.put_cache_a("203.0.113.2", common.time.time(),
                       generation=t["generation"])
    expired = common.expire_if_due(deadline + 0.01)
    tr4 = common.get_trial()
    check("U10 到期是原子转换并清空缓存",
          expired and tr4["status"] == "expired"
          and common.get_cache() is None
          and tr4["generation"] > t["generation"],
          f"expired={expired} status={tr4['status']}")
    check("U11 到期后基地址未改（仍是确认后的常驻地址）",
          common.get_control()["ip"] == "198.51.100.1")

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
