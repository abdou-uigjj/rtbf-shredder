"""tests for the sealed envelope store and pseudonymization."""

import os
import secrets

import pytest

from shredder.core import EnvelopeStore, MasterKeyError, pseudonymize, shred_file


def test_pseudonym_is_stable_and_salted(tmp_path):
    a = pseudonymize("REQ-1", "salt-x")
    assert a == pseudonymize("REQ-1", "salt-x")
    assert a != pseudonymize("REQ-1", "salt-y")
    assert a != pseudonymize("REQ-2", "salt-x")
    assert len(a) == 16


def test_pseudonym_rejects_empty_salt():
    with pytest.raises(ValueError):
        pseudonymize("REQ-1", "")


def test_envelope_roundtrip(tmp_path):
    store = EnvelopeStore(str(tmp_path / "store"), master_key=secrets.token_bytes(32))
    store.put("sid-1", "r1", b"patient referral notes")
    assert store.get("sid-1", "r1") == b"patient referral notes"
    assert store.list_subjects() == ["sid-1"]
    assert store.subject_records("sid-1") == ["r1"]


def test_box_files_hold_no_plaintext(tmp_path):
    store = EnvelopeStore(str(tmp_path / "store"), master_key=secrets.token_bytes(32))
    secret = b"CANARY-PLAINTEXT-MARKER-42"
    store.put("sid-1", "r1", secret)
    blob_files = []
    for dirpath, _dirs, names in os.walk(tmp_path / "store" / "subjects"):
        for n in names:
            p = os.path.join(dirpath, n)
            if p.endswith((".box", ".key")):
                blob_files.append(p)
    assert blob_files
    for p in blob_files:
        with open(p, "rb") as f:
            assert secret not in f.read(), f"plaintext leaked into {p}"


def test_master_key_permissions_enforced(tmp_path):
    root = tmp_path / "store"
    root.mkdir()
    mp = root / "master.key"
    mp.write_bytes(secrets.token_bytes(32))
    os.chmod(mp, 0o644)
    with pytest.raises(MasterKeyError):
        EnvelopeStore(str(root))
    os.chmod(mp, 0o600)
    EnvelopeStore(str(root))  # now fine


def test_master_key_size_enforced(tmp_path):
    with pytest.raises(MasterKeyError):
        EnvelopeStore(str(tmp_path / "s"), master_key=b"short")


def test_shred_record_destroys_and_unreads(tmp_path):
    store = EnvelopeStore(str(tmp_path / "store"), master_key=secrets.token_bytes(32))
    store.put("sid-1", "r1", b"one")
    store.put("sid-1", "r2", b"two")
    receipt = store.shred_record("sid-1", "r1")
    assert receipt["bytes_shredded"] > 0
    with pytest.raises(KeyError):
        store.get("sid-1", "r1")
    assert store.get("sid-1", "r2") == b"two"  # surgical
    assert store.subject_records("sid-1") == ["r2"]


def test_shred_subject_removes_everything(tmp_path):
    store = EnvelopeStore(str(tmp_path / "store"), master_key=secrets.token_bytes(32))
    for i in range(4):
        store.put("sid-x", f"r{i}", b"data" * 100)
    receipt = store.shred_subject("sid-x")
    assert receipt["records_shredded"] == 4
    assert store.list_subjects() == []
    assert not (tmp_path / "store" / "subjects" / "sid-x").exists()


def test_shredded_bytes_leave_no_plaintext(tmp_path):
    store = EnvelopeStore(str(tmp_path / "store"), master_key=secrets.token_bytes(32))
    marker = b"RTBF-UNIQUE-SHRED-MARKER-99"
    store.put("sid-1", "r1", b"x" * 10 + marker)  # note: stored sealed
    box_path = tmp_path / "store" / "subjects" / "sid-1" / "r1.box"
    box_path.write_bytes(b"RAW-MARKER-RTBF-UNIQUE-SHRED-MARKER-99-ECHO")
    store.shred_record("sid-1", "r1")
    raw = b"".join(p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())
    assert marker not in raw


def test_shred_file_two_passes(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"A" * 4096)
    n = shred_file(str(p))
    assert n == 4096
    assert not p.exists()
