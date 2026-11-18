"""surgical sqlite erasure, verified against the raw bytes.

the naive approach - `delete from patients where mrn = ?` - removes the
rows from the b-tree but leaves their bytes in freelist pages, in the
wal, and anywhere a page was never rewritten. our attacker proves that
in seconds. this engine erases surgically instead:

  1. locate every row of the subject (marker match on target columns)
  2. overwrite each target column in place with random bytes of the
     same length - the payload in the page becomes noise before any
     page ever gets freed
  3. delete the rows
  4. checkpoint and kill the wal/journal so no sidecar survives
  5. vacuum into a brand-new database file and atomically replace the
     old one - freelist pages do not survive a rebuild
  6. mechanically shred the replaced file's bytes before unlinking

every step is observable, the receipt records it all, and the drill
re-runs the attacker afterwards to prove the claim.
"""

import os
import secrets
import sqlite3

from ..attacker import scan

TARGET_MODE = 0o600


class SqliteEngine:
    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)

    # -- seeding (drill/test convenience) ---------------------------------
    def seed(self, table: str, schema: str, rows: list[dict]) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(schema)
            for r in rows:
                cols = ", ".join(r.keys())
                qs = ", ".join("?" for _ in r)
                conn.execute(f"insert into {table} ({cols}) values ({qs})",
                             tuple(r.values()))
            conn.commit()
        finally:
            conn.close()

    # -- attacker views ----------------------------------------------------
    def attacker_scan(self, markers: list[str]) -> dict:
        return scan(self.db_path, markers)

    # -- the surgical erase --------------------------------------------------
    def erase_subject(self, marker: str, table: str, columns: list[str]) -> dict:
        path = self.db_path
        before = scan(path, [marker])

        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            # sqlite builds differ: some compile with secure_delete (which
            # zeroes freed content for us), some do not. we do not rely on
            # either behavior - the in-place overwrite below is the layer
            # that must work - but enabling it costs nothing and adds one
            # more wall between the subject's bytes and a later reader.
            conn.execute("pragma secure_delete=on")
            # 1. locate the subject's rows
            where = " or ".join(f"{c} like ?" for c in columns)
            args = [f"%{marker}%"] * len(columns)
            rows = conn.execute(
                f"select rowid from {table} where {where}", args).fetchall()
            rowids = [r["rowid"] for r in rows]

            # 2. overwrite the payload in place, same length, random bytes
            overwritten = 0
            for rid in rowids:
                sets = []
                upd_args = []
                for c in columns:
                    cur = conn.execute(
                        f"select {c} from {table} where rowid=?", (rid,)).fetchone()[0]
                    raw = ("" if cur is None else str(cur)).encode()
                    if marker.encode() in raw:
                        blob = secrets.token_hex(max(1, len(raw))).encode()[: max(1, len(raw))]
                        sets.append(f"{c}=?")
                        upd_args.append(blob)
                        overwritten += len(raw)
                if sets:
                    conn.execute(
                        f"update {table} set {', '.join(sets)} where rowid=?",
                        upd_args + [rid])

            # 3. delete the rows
            if rowids:
                conn.execute(f"delete from {table} where rowid in "
                             f"({', '.join('?' * len(rowids))})", rowids)
            conn.commit()

            # 4. checkpoint and drop the sidecars so no residue survives
            conn.execute("pragma wal_checkpoint(truncate)")
            conn.execute("pragma journal_mode=delete")
            conn.commit()
        finally:
            conn.close()
        for suffix in ("-wal", "-shm", "-journal"):
            side = path + suffix
            if os.path.exists(side):
                _shred_and_unlink(side)

        # 5. rebuild into a fresh file; freelists and stale pages die here
        tmp = path + ".shredded.tmp"
        conn = sqlite3.connect(path)
        try:
            conn.execute("vacuum into ?", (tmp,))
            ok = conn.execute("pragma integrity_check").fetchone()[0]
        finally:
            conn.close()
        if ok != "ok":
            raise RuntimeError(f"integrity check failed after erasure: {ok}")

        # 6. shred the old file's bytes, then move the rebuild into place
        _shred_bytes(path)
        os.chmod(tmp, TARGET_MODE)
        os.replace(tmp, path)

        after = scan(path, [marker])
        return {
            "engine": "sqlite",
            "db": os.path.basename(path),
            "rows_erased": len(rowids),
            "payload_bytes_overwritten": overwritten,
            "recovery_before": {"fragments": before["total_fragments"],
                                "bytes": before["total_bytes_recoverable"]},
            "recovery_after": {"fragments": after["total_fragments"],
                               "bytes": after["total_bytes_recoverable"]},
        }


def _shred_bytes(path: str, passes: int = 1) -> int:
    size = os.path.getsize(path)
    if size == 0:
        return 0
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(secrets.token_bytes(size))
            f.flush()
            os.fsync(f.fileno())
    return size


def _shred_and_unlink(path: str) -> int:
    n = _shred_bytes(path)
    os.unlink(path)
    return n
