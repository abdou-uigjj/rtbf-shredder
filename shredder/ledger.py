"""the erasure ledger: an append-only, hash-chained record of every action.

each entry commits to the previous entry's hash, so the ledger is
tamper-evident: any edit to an old line breaks every hash after it, and
`verify()` walks the whole chain to prove it. the certificate binds to
the ledger head at issuance time, so a receipt is only worth something
while its chain checks out.

the ledger contains pseudonyms only. it is also the operational record a
DPO hands to an auditor: what was erased, by which engine, when, and
what the recovery attacker saw before and after.
"""

import hashlib
import json
import os
import time

GENESIS_HASH = "0" * 64


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def entry_hash(prev: str, entry: dict) -> str:
    body = dict(entry)
    body["prev"] = prev
    return hashlib.sha256(_canonical(body)).hexdigest()


class Ledger:
    """jsonl-backed hash chain. one canonical json object per line."""

    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("")
        self._entries: list[dict] | None = None

    # -- loading ----------------------------------------------------------
    def entries(self) -> list[dict]:
        if self._entries is None:
            out = []
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
            self._entries = out
        return self._entries

    def head(self) -> str:
        e = self.entries()
        return e[-1]["hash"] if e else GENESIS_HASH

    def __len__(self) -> int:
        return len(self.entries())

    # -- appending ----------------------------------------------------------
    def append(self, action: str, payload: dict) -> dict:
        prev = self.head()
        entry = {
            "seq": len(self.entries()),
            "ts": _now(),
            "action": action,
            "payload": payload,
        }
        entry["prev"] = prev
        entry["hash"] = entry_hash(prev, entry)
        with open(self.path, "a") as f:
            f.write(_canonical(entry).decode() + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._entries = None  # force re-read from disk
        return entry

    # -- verification ----------------------------------------------------------
    def verify(self) -> dict:
        """walk the chain. returns {ok, entries, broken_at, reason}."""
        prev = GENESIS_HASH
        for i, e in enumerate(self.entries()):
            recomputed = entry_hash(prev, {k: v for k, v in e.items() if k != "hash"})
            if e.get("prev") != prev:
                return {"ok": False, "entries": i, "broken_at": i,
                        "reason": f"entry {i} does not chain to its predecessor"}
            if e.get("hash") != recomputed:
                return {"ok": False, "entries": i + 1, "broken_at": i,
                        "reason": f"entry {i} hash mismatch - content was edited"}
            if e.get("seq") != i:
                return {"ok": False, "entries": i + 1, "broken_at": i,
                        "reason": f"entry {i} sequence number is wrong"}
            prev = e["hash"]
        return {"ok": True, "entries": len(self.entries()), "broken_at": None,
                "head": prev}
