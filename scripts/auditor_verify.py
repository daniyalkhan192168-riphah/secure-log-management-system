#!/usr/bin/env python3
"""
Independent auditor for the Secure Log Management System.

Run it on a DIFFERENT machine from the log server, with a copy of the
database and the auditor key K0 (which must never stay on the server):

    python auditor_verify.py --db secure_logs.db --k0 AUDITOR_K0.key

It uses only the Python standard library and re-implements every primitive
on purpose, so it does not trust any code from the server.

What it checks (everything the server checks, PLUS what only K0 allows):
  1. hash chain links and content hashes        (public)
  2. per-log HMAC with the correct batch key    (needs K0)
  3. Merkle root of every sealed batch          (public)
  4. HMAC seal of every sealed batch            (needs K0)
  5. seal chain, batch numbering, batch ranges  (public)

Exit code: 0 = valid, 1 = tampering found, 2 = usage / input error.
"""
import argparse
import hashlib
import hmac
import json
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime

GENESIS = "0" * 64


# ------------------------------------------------------------ primitives
def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_hash(payload, prev):
    return hashlib.sha256(b"SLv1-entry" + canonical(payload) + bytes.fromhex(prev)).hexdigest()


def log_mac(key, eh):
    return hmac.new(key, b"SLv1-mac" + bytes.fromhex(eh), hashlib.sha256).hexdigest()


def batch_seal(key, header):
    return hmac.new(key, b"SLv1-seal" + canonical(header), hashlib.sha256).hexdigest()


def evolve(key):
    return hashlib.sha256(b"SLv1-evolve" + key).digest()


def fingerprint(k0):
    return hashlib.sha256(b"SLv1-k0-fingerprint" + k0).hexdigest()


def merkle_root(hashes):
    if not hashes:
        return None
    level = [hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest() for h in hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
            else:
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


def ts_string(raw):
    # SQLAlchemy stores "YYYY-MM-DD HH:MM:SS.ffffff"
    return datetime.fromisoformat(raw).isoformat(timespec="microseconds")


# ------------------------------------------------------------ audit
def audit(db_path, k0, expected_fp=None):
    problems = []

    def bad(kind, detail, **where):
        problems.append({"type": kind, "detail": detail, **where})

    if expected_fp and fingerprint(k0) != expected_fp:
        bad("wrong_k0", "K0 does not match the published fingerprint")

    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    logs = con.execute("SELECT * FROM logs ORDER BY id").fetchall()
    roots = con.execute("SELECT * FROM merkle_roots ORDER BY batch_id").fetchall()
    con.close()

    sealed = {r["batch_id"]: r for r in roots}
    open_batch = (roots[-1]["batch_id"] if roots else 0) + 1
    max_batch = max([open_batch] + [l["batch_id"] for l in logs])

    keys, k = {}, k0
    for b in range(1, max_batch + 1):
        keys[b] = k
        k = evolve(k)

    # 1 + 2: chain, content hashes, per-log MACs
    prev = GENESIS
    by_batch = defaultdict(list)
    for l in logs:
        payload = {
            "id": l["id"], "timestamp": ts_string(l["timestamp"]),
            "source": l["source"], "event_type": l["event_type"],
            "username": l["username"], "ip_address": l["ip_address"],
            "message": l["message"], "agent_id": l["agent_id"],
            "event_time": ts_string(l["event_time"]) if l["event_time"] else None,
        }
        if l["previous_hash"] != prev:
            bad("chain_link", "previous_hash mismatch", log_id=l["id"])
        eh = entry_hash(payload, l["previous_hash"])
        if eh != l["current_hash"]:
            bad("content_hash", "content does not match stored hash", log_id=l["id"])
        # The MAC is checked against the hash recomputed from CONTENT, so a
        # rewritten chain cannot hide behind consistent-looking stored hashes.
        if not hmac.compare_digest(log_mac(keys[l["batch_id"]], eh), l["mac"] or ""):
            bad("mac", "HMAC invalid: log was changed or forged", log_id=l["id"], batch_id=l["batch_id"])
        if l["batch_id"] > open_batch:
            bad("orphan_batch", f"log claims batch {l['batch_id']} but open batch is {open_batch}", log_id=l["id"])
        by_batch[l["batch_id"]].append(l)
        prev = l["current_hash"]

    # 3 + 4 + 5: sealed batches
    prev_seal = GENESIS
    for i, r in enumerate(roots, start=1):
        b = r["batch_id"]
        if b != i:
            bad("missing_batch", f"expected batch {i}, found {b}", batch_id=b)
        batch_logs = by_batch.get(b, [])
        ids = [l["id"] for l in batch_logs]
        if (len(ids) != r["total_logs"] or not ids
                or ids[0] != r["first_log_id"] or ids[-1] != r["last_log_id"]):
            bad("batch_range", "logs added/removed after sealing", batch_id=b)
        if merkle_root([l["current_hash"] for l in batch_logs]) != r["root_hash"]:
            bad("merkle_root", "recomputed root differs from stored root", batch_id=b)
        if r["previous_seal"] != prev_seal:
            bad("seal_link", "seal chain broken", batch_id=b)
        header = {
            "batch_id": b, "first_log_id": r["first_log_id"], "last_log_id": r["last_log_id"],
            "total_logs": r["total_logs"], "root_hash": r["root_hash"],
            "previous_seal": r["previous_seal"], "key_version": r["key_version"],
        }
        if r["key_version"] != b or not hmac.compare_digest(batch_seal(keys[b], header), r["seal"]):
            bad("seal", "seal HMAC invalid: batch header or root was altered", batch_id=b)
        prev_seal = r["seal"]

    return {
        "status": "VALID" if not problems else "TAMPERED",
        "logs_checked": len(logs),
        "sealed_batches_checked": len(roots),
        "open_batch": open_batch,
        "problems": problems,
    }


def main():
    ap = argparse.ArgumentParser(description="Independent audit of a Secure Log database")
    ap.add_argument("--db", required=True, help="path to a COPY of secure_logs.db")
    ap.add_argument("--k0", required=True, help="path to AUDITOR_K0.key (hex)")
    ap.add_argument("--fingerprint", help="published K0 fingerprint (from GET /keys/current)")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args()

    try:
        with open(args.k0, encoding="utf-8") as f:
            k0 = bytes.fromhex(f.read().strip())
        report = audit(args.db, k0, args.fingerprint)
    except (OSError, ValueError, sqlite3.Error) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Result:          {report['status']}")
        print(f"Logs checked:    {report['logs_checked']}")
        print(f"Sealed batches:  {report['sealed_batches_checked']}")
        print(f"Open batch:      {report['open_batch']}")
        for p in report["problems"][:50]:
            where = ", ".join(f"{k}={v}" for k, v in p.items() if k not in ("type", "detail"))
            print(f"  [{p['type']}] {p['detail']} ({where})")
        if len(report["problems"]) > 50:
            print(f"  ... and {len(report['problems']) - 50} more")
    sys.exit(0 if report["status"] == "VALID" else 1)


if __name__ == "__main__":
    main()
