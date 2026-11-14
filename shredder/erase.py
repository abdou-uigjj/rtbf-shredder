"""the orchestrator: one call, every engine, one receipt set, one cert.

`erase_subject` is what the drill and the lambda both call. it runs the
configured engines against a subject pseudonym, appends every receipt
to the hash-chained ledger, and issues a signed erasure certificate
bound to the ledger head at the moment of issuance. the caller hands in
the master key material in memory; nothing here ever writes it.
"""

import hashlib

from .cert import issue_certificate
from .drivers.aws import AwsEngine
from .drivers.local import LocalEngine
from .drivers.sqlite_engine import SqliteEngine
from .ledger import Ledger


class ErasureTarget:
    """one storage engine bound to one subject erasure."""

    def __init__(self, engine, *, table: str | None = None,
                 columns: list[str] | None = None, bucket: str | None = None):
        self.engine = engine
        self.table = table
        self.columns = columns
        self.bucket = bucket


def request_ref_hash(request_ref: str, salt: str) -> str:
    return hashlib.sha256(f"req:{salt}:{request_ref}".encode()).hexdigest()


def erase_subject(
    *,
    sid: str,
    request_ref: str,
    salt: str,
    markers: list[str],
    targets: list[ErasureTarget],
    ledger: Ledger,
    signing_key: bytes,
    operator: str = "rtbf-shredder",
) -> dict:
    """erase one subject everywhere, prove it, sign it.

    markers are the canary byte patterns embedded in the subject's data
    (the drill plants them; production deployments seed them at write
    time). each engine returns a receipt with recovery_before/after;
    the ledger records them; the certificate commits to the ledger head.
    """
    if not markers:
        raise ValueError("no markers given - an erasure with no canary "
                         "bytes cannot be proven either way")
    receipts = []
    for t in targets:
        eng = t.engine
        if isinstance(eng, SqliteEngine):
            if not (t.table and t.columns):
                raise ValueError("sqlite target needs table + columns")
            receipts.append(eng.erase_subject(markers[0], t.table, t.columns))
        elif isinstance(eng, LocalEngine):
            receipts.append(eng.erase_subject(sid, markers))
        elif isinstance(eng, AwsEngine):
            if not t.bucket:
                raise ValueError("aws target needs a bucket")
            receipts.append(eng.erase_subject(t.bucket, sid, markers))
        else:
            raise TypeError(f"unknown engine type: {type(eng).__name__}")

    for r in receipts:
        ledger.append("engine-erasure", {"sid": sid, "receipt": r})
    cert_entry = ledger.append("erasure-certificate-issued",
                               {"sid": sid, "engines": [r["engine"] for r in receipts]})

    cert = issue_certificate(
        signing_key,
        subject_pseudonym=sid,
        request_ref_hash=request_ref_hash(request_ref, salt),
        engines=receipts,
        ledger_head=cert_entry["hash"],
        ledger_entries=len(ledger),
        operator=operator,
        scope=sorted({r["engine"] for r in receipts}),
    )
    return {"sid": sid, "receipts": receipts, "certificate": cert,
            "ledger_head": cert_entry["hash"]}
