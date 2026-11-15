"""tests for the aws kms simulation and the full orchestrator."""

import os
import secrets

import pytest

from shredder.cert import generate_keypair
from shredder.drivers.aws import AwsEngine
from shredder.drivers.local import LocalEngine
from shredder.erase import ErasureTarget, erase_subject, request_ref_hash
from shredder.ledger import Ledger


def mk_aws(tmp_path):
    aws = AwsEngine(str(tmp_path / "aws"))
    aws.create_tenant_key()
    return aws


def test_put_and_get_roundtrip(tmp_path):
    aws = mk_aws(tmp_path)
    aws.put_object("bkt", "sid-1", "chart", b"payload one")
    aws.put_object("bkt", "sid-1", "chart", b"payload two")
    assert aws.list_versions("bkt", "sid-1", "chart") == [1, 2]
    assert aws.get_object("bkt", "sid-1", "chart", 1) == b"payload one"
    assert aws.get_object("bkt", "sid-1", "chart", 2) == b"payload two"


def test_objects_are_sealed_on_disk(tmp_path):
    aws = mk_aws(tmp_path)
    secret = b"RTBF-AWS-PLAIN-MARKER-7"
    aws.put_object("bkt", "sid-1", "chart", secret)
    raw = open(tmp_path / "aws" / "s3" / "bkt" / "sid-1" / "chart.v1", "rb").read()
    assert secret not in raw


def test_erase_destroys_key_and_versions(tmp_path):
    aws = mk_aws(tmp_path)
    for i in range(3):
        aws.put_object("bkt", "sid-1", f"obj-{i}", b"x" * 500)
    receipt = aws.erase_subject("bkt", "sid-1", ["no-marker-expected"])
    assert receipt["data_keys_destroyed"] == 1
    assert receipt["objects_deleted"] == 3
    assert receipt["versions_scrubbed"] == 3
    assert not os.path.isdir(tmp_path / "aws" / "s3" / "bkt" / "sid-1")
    assert not os.path.exists(tmp_path / "aws" / "kms" / "tenant-primary.wraps" / "sid-1")
    with pytest.raises(Exception):
        aws.get_object("bkt", "sid-1", "obj-0", 1)


def test_erase_is_surgical_between_subjects(tmp_path):
    aws = mk_aws(tmp_path)
    aws.put_object("bkt", "sid-1", "chart", b"a data")
    aws.put_object("bkt", "sid-2", "chart", b"b data")
    aws.erase_subject("bkt", "sid-1", [])
    assert aws.get_object("bkt", "sid-2", "chart", 1) == b"b data"


def test_tenant_key_survives_subject_erase(tmp_path):
    """crypto-shred kills the DATA key, never the tenant cmk."""
    aws = mk_aws(tmp_path)
    aws.put_object("bkt", "sid-1", "chart", b"x")
    aws.put_object("bkt", "sid-9", "chart", b"y")
    aws.erase_subject("bkt", "sid-1", [])
    assert os.path.exists(tmp_path / "aws" / "kms" / "tenant-primary.cmk")
    assert aws.get_object("bkt", "sid-9", "chart", 1) == b"y"


# -- orchestrator -----------------------------------------------------------------

def test_orchestrator_end_to_end(tmp_path):
    salt = secrets.token_hex(8)
    sid = "sid-victim"
    marker = "RTBF-ORCH-MARKER-11"

    db_engine = __import__("shredder.drivers.sqlite_engine",
                           fromlist=["SqliteEngine"]).SqliteEngine(
        str(tmp_path / "c.db"))
    db_engine.seed("patients", "create table patients (name text, notes text)",
                   [{"name": "A (x)", "notes": f"ref {marker}"}])
    local = LocalEngine(str(tmp_path / "env"), master_key=secrets.token_bytes(32))
    local.seed(sid, "r1", f"letter {marker}".encode())
    aws = mk_aws(tmp_path)
    aws.put_object("bkt", sid, "chart", f"export {marker}".encode())

    led = Ledger(str(tmp_path / "ledger.jsonl"))
    sk, _ = generate_keypair()
    out = erase_subject(
        sid=sid, request_ref="REQ-42", salt=salt, markers=[marker],
        targets=[ErasureTarget(db_engine, table="patients", columns=["name", "notes"]),
                 ErasureTarget(local),
                 ErasureTarget(aws, bucket="bkt")],
        ledger=led, signing_key=sk, operator="dpo")

    engines = [r["engine"] for r in out["receipts"]]
    assert engines == ["sqlite", "local-envelope", "aws-kms-sim"]
    assert led.verify()["ok"] and len(led) == 4  # 3 receipts + cert entry
    cert = out["certificate"]
    assert cert["body"]["ledger_head_sha256"] == out["ledger_head"]
    assert cert["body"]["request_ref_hash"] == request_ref_hash("REQ-42", salt)
    db_engine.erase_subject if False else None
    assert db_engine.attacker_scan([marker])["total_fragments"] == 0


def test_orchestrator_refuses_markerless_erasure(tmp_path):
    led = Ledger(str(tmp_path / "l.jsonl"))
    sk, _ = generate_keypair()
    with pytest.raises(ValueError):
        erase_subject(sid="s", request_ref="r", salt="s", markers=[],
                      targets=[], ledger=led, signing_key=sk)


def test_orchestrator_sqlite_target_needs_table(tmp_path):
    from shredder.drivers.sqlite_engine import SqliteEngine
    led = Ledger(str(tmp_path / "l.jsonl"))
    sk, _ = generate_keypair()
    with pytest.raises(ValueError):
        erase_subject(sid="s", request_ref="r", salt="s",
                      markers=["m"],
                      targets=[ErasureTarget(SqliteEngine(str(tmp_path / "x.db")))],
                      ledger=led, signing_key=sk)
