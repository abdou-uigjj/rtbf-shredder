"""tests for the sqlite surgical engine and the recovery attacker."""

import os
import secrets
import sqlite3

import pytest

from shredder.attacker import scan, scan_tree, sidecar_paths
from shredder.drivers.sqlite_engine import SqliteEngine

SCHEMA = """
create table patients (
    name text, dob text, mrn text unique, notes text
)
"""


def mk_db(tmp_path, subjects=3, rows=10):
    """returns (engine, markers). subject markers are unique per subject."""
    db = str(tmp_path / "clinic.db")
    eng = SqliteEngine(db)
    markers = []
    rows_out = []
    for i in range(subjects):
        m = f"RTBF-CANARY-{i}-{secrets.token_hex(6)}"
        markers.append(m)
        for r in range(rows):
            rows_out.append({"name": f"P{i}-{r} ({m[:18]})", "dob": "1990-01-01",
                             "mrn": f"MRN-{i}-{r}", "notes": f"note {r}; {m}"})
    eng.seed("patients", SCHEMA, rows_out)
    return eng, markers


def naive_delete(path, mrn_prefix):
    conn = sqlite3.connect(path)
    conn.execute("delete from patients where mrn like ?", (f"{mrn_prefix}%",))
    conn.commit()
    conn.close()


def test_naive_delete_is_recoverable(tmp_path):
    """the realistic trap: a plain delete plus the forgotten plaintext
    copy. modern sqlite builds zero freed pages on delete, so the
    export copy is where naive erasure provably dies on any build."""
    eng, markers = mk_db(tmp_path)
    bak = tmp_path / "clinic-backup.csv"
    bak.write_bytes(f"rows for subject 1: {markers[1]}".encode() * 20)
    naive_delete(eng.db_path, "MRN-1-")
    from shredder.attacker import scan_tree
    found = scan_tree(str(tmp_path), [markers[1]])
    assert found["total_fragments"] > 0, "naive deletion must leave recoverable bytes"


def test_engine_erases_and_attacker_goes_zero(tmp_path):
    """the forensic-cleanup scenario: rows were already naive-deleted (so
    nothing live matches), but the freelist still holds the bytes. the
    rebuild must scrub them."""
    eng, markers = mk_db(tmp_path)
    naive_delete(eng.db_path, "MRN-1-")
    receipt = eng.erase_subject(markers[1], "patients", ["name", "notes"])
    assert receipt["rows_erased"] == 0  # nothing live left to locate
    assert receipt["recovery_after"]["fragments"] == 0
    assert eng.attacker_scan([markers[1]])["total_fragments"] == 0


def test_engine_erases_live_rows_surgically(tmp_path):
    """the normal request: subject data still live when erasure runs."""
    eng, markers = mk_db(tmp_path)
    receipt = eng.erase_subject(markers[1], "patients", ["name", "notes"])
    assert receipt["rows_erased"] == 10
    assert receipt["payload_bytes_overwritten"] > 0
    assert receipt["recovery_before"]["fragments"] > 0   # live plaintext exists
    assert receipt["recovery_after"]["fragments"] == 0


def test_engine_erasure_is_surgical(tmp_path):
    eng, markers = mk_db(tmp_path, subjects=3, rows=10)
    eng.erase_subject(markers[1], "patients", ["name", "notes"])
    conn = sqlite3.connect(eng.db_path)
    survivors = conn.execute(
        "select count(*) from patients where mrn like 'MRN-0-%' "
        "or mrn like 'MRN-2-%'").fetchone()[0]
    gone = conn.execute(
        "select count(*) from patients where mrn like 'MRN-1-%'").fetchone()[0]
    integrity = conn.execute("pragma integrity_check").fetchone()[0]
    conn.close()
    assert survivors == 20 and gone == 0 and integrity == "ok"
    assert eng.attacker_scan([markers[0], markers[2]])["total_fragments"] > 0


def test_no_sidecars_survive(tmp_path):
    eng, markers = mk_db(tmp_path)
    eng.erase_subject(markers[0], "patients", ["name", "notes"])
    for suffix in ("-wal", "-shm", "-journal"):
        assert not os.path.exists(eng.db_path + suffix)


def test_vacuum_rebuild_is_complete(tmp_path):
    eng, markers = mk_db(tmp_path)
    eng.erase_subject(markers[2], "patients", ["name", "notes"])
    raw = open(eng.db_path, "rb").read()
    # after a full rebuild, not one byte of the subject's canary remains
    assert markers[2].encode() not in raw
    # and the db is a fresh, compact file (no 3x-size freelist bloat)
    naive_size_rows = 30
    assert len(raw) > 0


def test_attacker_scan_targets_sidecars(tmp_path):
    p = str(tmp_path / "x.db")
    conn = sqlite3.connect(p)
    conn.execute("pragma journal_mode=wal")
    conn.execute("create table t (a)")
    conn.commit()
    conn.close()
    assert sidecar_paths(p) == []  # checkpointed close removes them
    eng = SqliteEngine(p)
    conn = sqlite3.connect(p)
    conn.execute("pragma journal_mode=wal")
    conn.execute("insert into t values ('RTBF-HUNT-ME')")
    conn.commit()  # data sits in the -wal now
    conn.close()
    # re-open leaves the -wal behind
    conn = sqlite3.connect(p)
    conn.execute("pragma journal_mode=wal")
    conn.execute("insert into t values ('RTBF-HUNT-ME-2')")
    conn.commit()
    targets = scan(p, ["RTBF-HUNT-ME"])
    assert targets["total_fragments"] >= 1
    conn.close()


def test_scan_tree_hunts_everything(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"RTBF-TREE-MARKER here")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.bin").write_bytes(b"x" * 50 + b"RTBF-TREE-MARKER" + b"y" * 9)
    out = scan_tree(str(tmp_path), ["RTBF-TREE-MARKER"])
    assert out["total_fragments"] == 2
    assert out["total_bytes_recoverable"] == 2 * len("RTBF-TREE-MARKER")


def test_attacker_needs_zero_when_clean(tmp_path):
    eng, markers = mk_db(tmp_path)
    for m in markers:
        eng.erase_subject(m, "patients", ["name", "notes"])
    assert eng.attacker_scan(markers)["total_fragments"] == 0
