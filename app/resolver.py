"""Caching UDP DNS resolver for one fixed internal domain.

Behaviour (all timings from app.common, defaults are the spec values):

  * a successful A answer is cached fresh for FRESH_TTL (5s) and served from
    cache with the remaining TTL;
  * after expiry the resolver re-fetches.  If the upstream times out (or its
    reply is unusable) the old A record may be served stale for at most
    STALE_WINDOW (20s) past expiry; beyond that the answer is SERVFAIL;
  * NXDOMAIN is cached fresh only -- it is never used as stale backup;
  * confirming NXDOMAIN purges the old A record durably (SQLite), so no later
    answer contains the old A again;
  * every upstream attempt uses a dedicated socket with a random transaction
    ID and matches the question section, so a late answer to an already
    timed-out query is never read and can never resurrect the old A;
  * cache deadlines are absolute epochs persisted in SQLite, so a restart does
    not extend the validity of an old A record.

Trial cut-over interaction:

  * the authoritative endpoint switches to a trial IPv4 the moment the trial
    starts; the transition deletes the resolver cache in the same committed
    transaction, so a query issued afterwards can never be answered from the
    previous state;
  * every trial/control transition bumps a persisted ``generation``.  A fetch
    remembers the generation it was started in and only writes its result back
    if the generation is unchanged, so an upstream reply that arrives after the
    state changed cannot re-insert the now-invalid address;
  * if the generation changes while a query is being resolved, the query is
    re-resolved against the new state (bounded), rather than answering with the
    stale state.

The resolver reports where each answer came from in an additional-section TXT
record (_src.<domain> TXT "source=upstream|cache-fresh|cache-stale|none ...")
and logs every query to the query_log table for the web console.
"""
from __future__ import annotations

import random
import socket
import threading
import time
import traceback

from dnslib import A, CLASS, QTYPE, RCODE, RR, TXT, DNSHeader, DNSRecord

from . import common

MAX_STATE_RETRIES = 3


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def upstream_query() -> DNSRecord | None:
    """One-shot upstream A query for the fixed domain.

    A dedicated UDP socket per attempt plus a random transaction ID means a
    late answer to an earlier, already timed-out query can never be read back
    (the socket is closed) and can never be mistaken for the answer to a later
    query (ID + question must match).
    """
    query = DNSRecord.question(common.FQDN, "A")
    query.header.id = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        deadline = time.monotonic() + common.UPSTREAM_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            if not _same_name(resp.q.qname, query.q.qname):
                continue
            return resp
    except OSError:
        return None
    finally:
        sock.close()


def _a_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.A, CLASS.IN, ttl, A(ip))


def _reply(query: DNSRecord, rcode: int, answers=(), source="none", detail="") -> DNSRecord:
    rep = DNSRecord(
        DNSHeader(
            id=query.header.id, qr=1, aa=0, ra=1, rd=query.header.rd, rcode=rcode
        ),
        q=query.q,
    )
    for rr in answers:
        rep.add_answer(rr)
    meta = f"source={source}" + (f" {detail}" if detail else "")
    rep.add_ar(RR(f"_src.{common.FQDN}", QTYPE.TXT, CLASS.IN, 0, TXT(meta)))
    return rep


def _cached_reply(query: DNSRecord, row: dict, now: float):
    """Answer from a cache row if it is fresh; return (reply, source, detail)."""
    if row and row["rcode"] == "NOERROR" and row["a_record"] and now < row["fresh_until"]:
        ttl = max(1, int(row["fresh_until"] - now + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh A from cache",
        )
    if row and row["rcode"] == "NXDOMAIN" and now < row["fresh_until"]:
        return (
            _reply(query, RCODE.NXDOMAIN, [], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh NXDOMAIN from cache",
        )
    return None


def resolve_a(query: DNSRecord) -> tuple[DNSRecord, str, str]:
    """Resolve the fixed domain's A record.  Returns (reply, source, detail)."""
    for _attempt in range(MAX_STATE_RETRIES):
        now = time.time()
        trial, _control, row = common.snapshot(now)
        generation = int(trial["generation"])

        # 1) fresh cache hits
        hit = _cached_reply(query, row, now)
        if hit is not None:
            return hit

        # 2) expired: ask the authoritative endpoint
        resp = upstream_query()
        now2 = time.time()

        if resp is not None and resp.header.rcode == RCODE.NOERROR:
            ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
            if ips:
                # Guarded write: if the state changed during the fetch, this is
                # a reply from a state that no longer exists -- drop it and
                # re-resolve against the new state.
                if common.put_cache_a(ips[0], now2, generation=generation):
                    return (
                        _reply(query, RCODE.NOERROR,
                               [_a_rr(ips[0], int(common.FRESH_TTL))], "upstream"),
                        "upstream",
                        f"fetched A={ips[0]}",
                    )
                continue

        if resp is not None and resp.header.rcode == RCODE.NXDOMAIN:
            # Confirming NXDOMAIN purges the old A record (durably, in SQLite).
            if common.put_cache_nxdomain(now2, generation=generation):
                return (
                    _reply(query, RCODE.NXDOMAIN, [], "upstream", "nxdomain-confirmed"),
                    "upstream",
                    "NXDOMAIN confirmed; old A purged",
                )
            continue

        # 3) upstream timeout / unusable reply: maybe serve the stale A record
        #    (NXDOMAIN is never served stale).  Re-read the state so a cache
        #    invalidated while we were waiting is never served.
        trial2, _c2, row2 = common.snapshot(now2)
        if int(trial2["generation"]) != generation:
            continue  # state changed: re-resolve instead of serving old data
        if (
            row2
            and row2["rcode"] == "NOERROR"
            and row2["a_record"]
            and row2["stale_until"]
            and now2 < row2["stale_until"]
        ):
            ttl = max(1, int(row2["stale_until"] - now2 + 0.999))
            return (
                _reply(query, RCODE.NOERROR, [_a_rr(row2["a_record"], ttl)],
                       "cache-stale", f"stale_left={row2['stale_until'] - now2:.1f}"),
                "cache-stale",
                "upstream timeout; serving stale A",
            )

        return (
            _reply(query, RCODE.SERVFAIL, [], "none", "upstream-timeout"),
            "none",
            "upstream timeout; no usable cache",
        )

    # The state kept changing under us: fail closed rather than answer with a
    # value that may belong to a superseded trial/control state.
    return (
        _reply(query, RCODE.SERVFAIL, [], "none", "state-churn"),
        "none",
        "state changed during resolution",
    )


def handle_packet(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        if not _same_name(query.q.qname, common.FQDN):
            rep = _reply(query, RCODE.REFUSED, [], "none", "out-of-scope")
            source, detail = "none", "out-of-scope"
        elif query.q.qtype == QTYPE.A:
            rep, source, detail = resolve_a(query)
        else:
            rep = _reply(query, RCODE.NOERROR, [], "none", "nodata")
            source, detail = "none", "nodata"
        sock.sendto(rep.pack(), addr)
        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers, detail)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.RESOLVER_PORT))
    print(
        f"[resolver] {common.FQDN} on udp/{common.RESOLVER_PORT}, "
        f"upstream {common.AUTH_HOST}:{common.AUTH_PORT}, "
        f"fresh={common.FRESH_TTL}s stale={common.STALE_WINDOW}s "
        f"timeout={common.UPSTREAM_TIMEOUT}s",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_packet, args=(data, addr, sock),
                         daemon=True).start()


if __name__ == "__main__":
    main()
