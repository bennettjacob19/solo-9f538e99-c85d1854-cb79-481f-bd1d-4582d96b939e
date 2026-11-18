#!/usr/bin/env python3
"""End-to-end self-test for the trial cut-over (试切) feature.

Spawns auth + resolver + web on loopback with the production timing
parameters (fresh TTL 5s, stale window 20s, upstream timeout 2s) and drives
the trial interleavings:

  G. trial takes effect immediately for new real UDP queries, page shows the
     trial number / remaining time / query answer
  H. confirm within the deadline makes the address permanent and invalidates
     the cache atomically
  I. revoke restores the original address at once
  J. expiry rolls back automatically; late confirmation is rejected; the old
     trial number cannot affect a later trial
  K. a normal mode switch terminates the trial; the old trial number is dead
  L. a late upstream answer from the previous state cannot re-enter the cache
     (delayed auth reply spanning a trial start), and the cache is not reused
     across the transition
  M. restart during a trial keeps the original absolute deadline

Exits non-zero if any check fails.  Runtime: ~100s.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dnslib import QTYPE, DNSRecord  # noqa: E402

DOMAIN = "service.example"
AUTH_PORT, RES_PORT, WEB_PORT = 16354, 16353, 19000
TMP = tempfile.mkdtemp(prefix="dns-trial-selftest-")
DB = os.path.join(TMP, "app.db")

env = dict(os.environ)
env.update(
    DB_PATH=DB,
    FIXED_DOMAIN=DOMAIN,
    AUTH_HOST="127.0.0.1",
    AUTH_PORT=str(AUTH_PORT),
    RESOLVER_HOST="127.0.0.1",
    RESOLVER_PORT=str(RES_PORT),
    WEB_PORT=str(WEB_PORT),
    FRESH_TTL="5",
    STALE_WINDOW="20",
    UPSTREAM_TIMEOUT="2",
    DEFAULT_IP="192.0.2.10",
    DEFAULT_DELAY="3",
    TRIAL_MIN_SECONDS="10",
    TRIAL_MAX_SECONDS="60",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)

procs: dict[str, subprocess.Popen] = {}
FAILS: list[str] = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def start(name: str, module: str) -> None:
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    procs[name] = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(name: str) -> None:
    p = procs.get(name)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def post(path: str, body: dict | None = None, expect_error: bool = False):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{WEB_PORT}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        if not expect_error:
            raise
        return e.code, json.load(e)


def get_state() -> dict:
    with urllib.request.urlopen(
            f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=5) as r:
        return json.load(r)


def set_control_direct(mode: str, ip: str = "192.0.2.10", delay: float = 3.0):
    """Bypass the web endpoint (simulates the base record from another path)."""
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute(
        "INSERT INTO control(id, mode, ip, delay_seconds, updated_at)"
        " VALUES (1, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, ip=excluded.ip,"
        " delay_seconds=excluded.delay_seconds, updated_at=excluded.updated_at",
        (mode, ip, delay, time.time()),
    )
    conn.commit()
    conn.close()


def get_cache() -> dict | None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM cache WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def get_control() -> dict:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM control WHERE id = 1").fetchone()
    conn.close()
    return dict(row)


def get_trial() -> dict:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM trial WHERE id = 1").fetchone()
    conn.close()
    return dict(row)


def clear_cache() -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("DELETE FROM cache WHERE id = 1")
    conn.commit()
    conn.close()


def dns_query(timeout: float = 8) -> tuple[int, list[tuple], str | None]:
    """Returns (rcode, [(type, data, ttl)], source)."""
    q = DNSRecord.question(DOMAIN, "A")
    data = q.send("127.0.0.1", RES_PORT, timeout=timeout)
    rep = DNSRecord.parse(data)
    answers = [(QTYPE[rr.rtype], str(rr.rdata), rr.ttl) for rr in rep.rr]
    src = None
    for rr in rep.ar:
        if rr.rtype == QTYPE.TXT:
            txt = str(rr.rdata).strip('"')
            if txt.startswith("source="):
                src = txt.split("=", 1)[1].split()[0]
    return rep.header.rcode, answers, src


def bg_query(results: list, delay: float = 0.0) -> threading.Thread:
    def run():
        if delay:
            time.sleep(delay)
        try:
            results.append(dns_query())
        except Exception as exc:  # noqa: BLE001
            results.append(("ERR", str(exc), None))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def sleep_until(ts: float) -> None:
    time.sleep(max(0.0, ts - time.time()))


def wait_resolver_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dns_query()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_web_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            get_state()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def ip_of(ans) -> str | None:
    return ans[0][1] if ans else None


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------
def main() -> int:
    print(f"[trial-selftest] workdir={TMP}", flush=True)
    start("auth", "app.auth_server")
    start("resolver", "app.resolver")
    start("web", "app.web")
    try:
        if not (wait_resolver_ready() and wait_web_ready()):
            print("  [FAIL] services did not come up", flush=True)
            return 1

        # -- G. trial takes effect immediately for new real queries ----------
        print("G. 试切立即对新查询生效；页面显示编号/剩余时间/查询答复", flush=True)
        set_control_direct("a", "192.0.2.10")
        clear_cache()
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src} {ans}"
        # Prime a fresh cache with the old address so invalidation is observable.
        rc, ans, src = dns_query()
        assert src == "cache-fresh" and ip_of(ans) == "192.0.2.10", f"{ans} {src}"

        code, res = post("/api/trial/start",
                         {"ip": "198.51.100.77", "deadline_seconds": 30})
        check("G1 试切开始被接受", code == 200 and res["ok"], f"code={code} res={res}")
        trial_no = get_trial()["trial_no"]
        check("G2 返回并持久化试切编号",
              trial_no and res["trial"]["trial_no"] == trial_no, f"no={trial_no}")
        t0 = time.time()
        rc, ans, src = dns_query()
        check("G3 新查询立即得到试切地址（不沿用旧缓存）",
              rc == 0 and ip_of(ans) == "198.51.100.77" and time.time() - t0 < 1.5,
              f"ans={ans} src={src} 耗时={time.time()-t0:.2f}s")
        check("G4 缓存已被清空且属于新 generation",
              (get_cache() is None) or (get_cache()["a_record"] == "198.51.100.77"),
              f"cache={get_cache()}")
        rc, ans, src = dns_query()
        check("G5 后续查询命中试切地址的新鲜缓存",
              rc == 0 and ip_of(ans) == "198.51.100.77" and src == "cache-fresh",
              f"ans={ans} src={src}")
        st = get_state()
        check("G6 页面状态含试切编号、剩余时间与查询日志",
              st["trial"]["trial_no"] == trial_no
              and st["trial"]["status"] == "active"
              and 0 < st["trial_remaining"] <= 30
              and any(r["source"] == "cache-fresh" for r in st["resolver_log"]),
              f"trial={st['trial']} remaining={st['trial_remaining']}")
        code, res = post("/api/trial/start",
                         {"ip": "198.51.100.77", "deadline_seconds": 5},
                         expect_error=True)
        check("G7 期限小于 10 秒被拒绝", code == 400 and not res["ok"],
              f"code={code} res={res}")
        code, res = post("/api/trial/start",
                         {"ip": "198.51.100.77", "deadline_seconds": 61},
                         expect_error=True)
        check("G8 期限大于 60 秒被拒绝", code == 400 and not res["ok"],
              f"code={code} res={res}")
        code, res = post("/api/trial/start",
                         {"ip": "not-an-ip", "deadline_seconds": 20},
                         expect_error=True)
        check("G9 非法 IPv4 被拒绝", code == 400 and not res["ok"],
              f"code={code} res={res}")

        # -- H. confirm makes it permanent, atomically with cache drop --------
        print("H. 期限内确认 -> 常驻；同一次提交使缓存失效", flush=True)
        code, res = post("/api/trial/confirm", {"trial_no": trial_no})
        check("H1 确认成功", code == 200 and res["ok"], f"code={code} res={res}")
        ctl = get_control()
        tr = get_trial()
        check("H2 基地址已变为试切地址、试切状态为已确认",
              ctl["ip"] == "198.51.100.77" and tr["status"] == "confirmed"
              and tr["ended_at"] is not None, f"ctl={ctl} trial={tr}")
        rc, ans, src = dns_query()
        check("H3 确认后新查询返回常驻地址（回源，不沿用旧缓存）",
              rc == 0 and ip_of(ans) == "198.51.100.77" and src == "upstream",
              f"ans={ans} src={src}")
        code, res = post("/api/trial/confirm", {"trial_no": trial_no},
                         expect_error=True)
        check("H4 重复确认被拒绝（编号已结束）", code == 409 and not res["ok"],
              f"code={code} res={res}")

        # -- I. revoke restores the original address -------------------------
        print("I. 撤销 -> 立即恢复原地址", flush=True)
        set_control_direct("a", "192.0.2.10")
        clear_cache()
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        code, res = post("/api/trial/start",
                         {"ip": "203.0.113.9", "deadline_seconds": 25})
        trial_no = res["trial"]["trial_no"]
        rc, ans, src = dns_query()
        check("I1 试切中返回新地址", ip_of(ans) == "203.0.113.9", f"ans={ans}")
        code, res = post("/api/trial/revoke", {"trial_no": trial_no})
        check("I2 撤销成功", code == 200 and res["ok"], f"code={code} res={res}")
        rc, ans, src = dns_query()
        check("I3 撤销后立即恢复原地址（回源）",
              rc == 0 and ip_of(ans) == "192.0.2.10" and src == "upstream",
              f"ans={ans} src={src}")
        check("I4 试切状态为已撤销", get_trial()["status"] == "revoked")
        code, res = post("/api/trial/revoke", {"trial_no": trial_no},
                         expect_error=True)
        check("I5 重复撤销被拒绝", code == 409 and not res["ok"],
              f"code={code} res={res}")

        # -- J. expiry rolls back; late confirm rejected; old number is dead -
        print("J. 逾期自动恢复；逾期确认被拒绝；旧编号不影响后续", flush=True)
        set_control_direct("a", "192.0.2.10")
        clear_cache()
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        code, res = post("/api/trial/start",
                         {"ip": "203.0.113.50", "deadline_seconds": 10})
        old_no = res["trial"]["trial_no"]
        deadline = get_trial()["deadline"]
        rc, ans, src = dns_query()
        check("J1 试切中返回新地址", ip_of(ans) == "203.0.113.50", f"ans={ans}")
        # Confirming after the absolute deadline must be rejected (the trial
        # has already auto-rolled back).
        rc, ans, src = dns_query()
        sleep_until(deadline + 0.2)
        code, res = post("/api/trial/confirm", {"trial_no": old_no},
                         expect_error=True)
        check("J2 到期后确认被拒绝",
              code == 409 and not res["ok"], f"code={code} res={res}")
        rc, ans, src = dns_query()
        check("J3 逾期自动恢复原地址",
              rc == 0 and ip_of(ans) == "192.0.2.10"
              and get_trial()["status"] == "expired",
              f"ans={ans} src={src} trial={get_trial()['status']}")

        # A new trial, then a stale confirm/revoke with the old number must not
        # disturb it.
        code, res = post("/api/trial/start",
                         {"ip": "203.0.113.60", "deadline_seconds": 20})
        new_no = res["trial"]["trial_no"]
        code, res = post("/api/trial/confirm", {"trial_no": old_no},
                         expect_error=True)
        check("J4 旧编号的确认不能影响新试切",
              code == 409 and get_trial()["trial_no"] == new_no
              and get_trial()["status"] == "active",
              f"code={code} trial={get_trial()}")
        code, res = post("/api/trial/revoke", {"trial_no": old_no},
                         expect_error=True)
        rc, ans, src = dns_query()
        check("J5 旧编号的撤销不能影响新试切",
              code == 409 and get_trial()["status"] == "active"
              and ip_of(ans) == "203.0.113.60", f"code={code} ans={ans}")
        # Old-trial expiry path: the deadline already passed for the old trial;
        # let the new one expire naturally and ensure it did not inherit it.
        new_deadline = get_trial()["deadline"]
        sleep_until(new_deadline + 0.5)
        rc, ans, src = dns_query()
        check("J6 新试切按自己的期限到期恢复",
              rc == 0 and ip_of(ans) == "192.0.2.10"
              and get_trial()["status"] == "expired",
              f"ans={ans} trial={get_trial()['status']}")

        # -- K. a normal mode switch terminates the trial --------------------
        print("K. 普通模式切换终止试切；旧编号失效", flush=True)
        set_control_direct("a", "192.0.2.10")
        clear_cache()
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        code, res = post("/api/trial/start",
                         {"ip": "203.0.113.70", "deadline_seconds": 30})
        trial_no = res["trial"]["trial_no"]
        rc, ans, src = dns_query()
        check("K1 试切进行中", ip_of(ans) == "203.0.113.70", f"ans={ans}")
        code, res = post("/api/mode", {"mode": "a", "ip": "192.0.2.20"})
        check("K2 普通模式切换成功并报告终止试切",
              code == 200 and res["ok"] and res.get("trial_cancelled"),
              f"code={code} res={res}")
        check("K3 试切状态为已被终止", get_trial()["status"] == "cancelled",
              f"trial={get_trial()['status']}")
        rc, ans, src = dns_query()
        check("K4 新查询立即使用普通模式地址",
              rc == 0 and ip_of(ans) == "192.0.2.20", f"ans={ans} src={src}")
        code, res = post("/api/trial/confirm", {"trial_no": trial_no},
                         expect_error=True)
        check("K5 被终止试切的旧编号不能确认",
              code == 409 and not res["ok"], f"code={code} res={res}")
        # Its deadline passing later must not undo the new setting.
        deadline = get_trial()["deadline"]
        if deadline:
            sleep_until(deadline + 0.4)
        rc, ans, src = dns_query()
        check("K6 旧试切到期处理不覆盖后续设置",
              get_control()["ip"] == "192.0.2.20"
              and rc == 0 and ip_of(ans) == "192.0.2.20", f"ans={ans}")

        # -- L. late upstream answer cannot cross a state transition ---------
        print("L. 状态改变前发出的回源迟到返回，不能写回失效地址", flush=True)
        set_control_direct("a", "192.0.2.10")
        clear_cache()
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        # Make the auth endpoint answer the OLD address slowly (3s > 2s timeout).
        set_control_direct("delay", "192.0.2.10", 3.0)
        time.sleep(5.5)  # let the fresh cache expire
        results: list = []
        t = bg_query(results, delay=0.05)
        time.sleep(0.4)  # the resolver is now waiting on the slow upstream
        code, res = post("/api/trial/start",
                         {"ip": "203.0.113.99", "deadline_seconds": 30})
        check("L1 试切在回源等待期间开始", code == 200 and res["ok"])
        t.join(timeout=10)
        # The in-flight query must not return the old address; it re-resolves
        # against the new state.
        rc, ans, src = results[0] if results else (None, [], None)
        check("L2 改变状态时在途查询不复用旧地址",
              rc == 0 and ip_of(ans) == "203.0.113.99",
              f"rc={rc} ans={ans} src={src}")
        # The late old answer arrived after the transition. Give it time and
        # ensure it did not replace the trial address in the cache.
        time.sleep(2.0)
        cache = get_cache()
        check("L3 迟到的旧答复未写回缓存",
              cache is None or cache["a_record"] in (None, "203.0.113.99"),
              f"cache={cache}")
        rc, ans, src = dns_query()
        check("L4 新查询仍得到试切地址",
              rc == 0 and ip_of(ans) == "203.0.113.99", f"ans={ans} src={src}")
        post("/api/trial/revoke", {"trial_no": get_trial()["trial_no"]})
        set_control_direct("a", "192.0.2.10")

        # -- M. restart during a trial keeps the absolute deadline -----------
        print("M. 试切期间重启仍按原绝对期限到期", flush=True)
        clear_cache()
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        code, res = post("/api/trial/start",
                         {"ip": "203.0.113.120", "deadline_seconds": 15})
        deadline = get_trial()["deadline"]
        stop("resolver")
        stop("web")
        time.sleep(1)
        start("resolver", "app.resolver")
        start("web", "app.web")
        assert wait_resolver_ready() and wait_web_ready(), "services did not return"
        rc, ans, src = dns_query()
        check("M1 重启后仍在试切中（绝对期限未延长）",
              rc == 0 and ip_of(ans) == "203.0.113.120"
              and get_trial()["deadline"] == deadline,
              f"ans={ans} src={src} deadline={deadline}")
        sleep_until(deadline + 0.5)
        rc, ans, src = dns_query()
        check("M2 到达原期限后自动恢复原地址",
              rc == 0 and ip_of(ans) == "192.0.2.10"
              and get_trial()["status"] == "expired",
              f"ans={ans} trial={get_trial()['status']}")

        # -- N. ordinary TTL / NXDOMAIN / timeout rules still apply ----------
        print("N. 原有 TTL / NXDOMAIN / 超时规则继续适用", flush=True)
        set_control_direct("a", "192.0.2.30")
        clear_cache()
        rc, ans, src = dns_query()
        check("N1 正常回源 TTL=5", rc == 0 and ans == [("A", "192.0.2.30", 5)]
              and src == "upstream", f"ans={ans} src={src}")
        rc, ans, src = dns_query()
        check("N2 新鲜缓存 TTL 倒数", src == "cache-fresh"
              and 1 <= ans[0][2] <= 5, f"ans={ans}")
        set_control_direct("nxdomain")
        time.sleep(5.5)
        rc, ans, src = dns_query()
        check("N3 确认 NXDOMAIN 并清除旧 A",
              rc == 3 and get_cache()["a_record"] is None, f"rc={rc}")
        set_control_direct("timeout")
        time.sleep(5.5)
        rc, ans, src = dns_query()
        check("N4 NXDOMAIN 无 stale 备用 -> SERVFAIL",
              rc == 2 and not ans, f"rc={rc} ans={ans}")

    finally:
        for name in list(procs):
            stop(name)
        print(f"[trial-selftest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
