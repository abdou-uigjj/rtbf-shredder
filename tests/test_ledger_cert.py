"""tests for the hash-chained erasure ledger and the signed certificate."""

import base64

import pytest

from nacl.signing import SigningKey

from shredder.cert import generate_keypair, issue_certificate, verify_certificate
from shredder.ledger import GENESIS_HASH, Ledger


def test_empty_ledger_has_genesis_head(tmp_path):
    led = Ledger(str(tmp_path / "l.jsonl"))
    assert len(led) == 0
    assert led.head() == GENESIS_HASH


def test_chain_verify_ok_and_head_moves(tmp_path):
    led = Ledger(str(tmp_path / "l.jsonl"))
    e1 = led.append("engine-erasure", {"sid": "s1", "receipt": {"n": 1}})
    e2 = led.append("erasure-certificate-issued", {"sid": "s1"})
    v = led.verify()
    assert v["ok"] and v["entries"] == 2
    assert e1["prev"] == GENESIS_HASH
    assert e2["prev"] == e1["hash"]
    assert led.head() == e2["hash"]


def test_tampered_payload_breaks_chain(tmp_path):
    p = tmp_path / "l.jsonl"
    led = Ledger(str(p))
    led.append("engine-erasure", {"sid": "s1", "receipt": {"bytes": 100}})
    led.append("erasure-certificate-issued", {"sid": "s1"})
    lines = p.read_text().splitlines()
    obj = __import__("json").loads(lines[0])
    obj["payload"]["receipt"]["bytes"] = 1
    lines[0] = __import__("json").dumps(obj, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")
    v = Ledger(str(p)).verify()
    assert not v["ok"] and v["broken_at"] == 0


def test_tampered_seq_breaks_chain(tmp_path):
    p = tmp_path / "l.jsonl"
    led = Ledger(str(p))
    led.append("a", {"x": 1})
    led.append("b", {"x": 2})
    lines = p.read_text().splitlines()
    obj = __import__("json").loads(lines[1])
    obj["seq"] = 5
    import json as j
    lines[1] = j.dumps(obj, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")
    assert not Ledger(str(p)).verify()["ok"]


def test_dropped_entry_breaks_chain(tmp_path):
    p = tmp_path / "l.jsonl"
    led = Ledger(str(p))
    led.append("a", {"x": 1})
    led.append("b", {"x": 2})
    led.append("c", {"x": 3})
    lines = p.read_text().splitlines()
    del lines[1]  # remove the middle entry entirely
    p.write_text("\n".join(lines) + "\n")
    v = Ledger(str(p)).verify()
    assert not v["ok"]


# -- certificates ---------------------------------------------------------------

def _cert():
    sk, _vk = generate_keypair()
    return issue_certificate(
        sk,
        subject_pseudonym="ab12cd34ef56ab12",
        request_ref_hash="deadbeef" * 8,
        engines=[{"engine": "sqlite", "rows_erased": 40, "recovery_after": {"fragments": 0}}],
        ledger_head="f" * 64,
        ledger_entries=3,
        operator="clinic-dpo",
        scope=["sqlite"],
    )


def test_certificate_verifies():
    assert verify_certificate(_cert())["ok"]


def test_certificate_body_tamper_fails():
    cert = _cert()
    cert["body"]["subject_pseudonym"] = "ffffffffffffffff"
    assert not verify_certificate(cert)["ok"]


def test_certificate_signature_swap_fails():
    cert = _cert()
    sig = bytearray(base64.b64decode(cert["signature"]))
    sig[0] ^= 0xFF
    cert["signature"] = base64.b64encode(bytes(sig)).decode()
    assert not verify_certificate(cert)["ok"]


def test_certificate_wrong_key_fails():
    cert = _cert()
    seed2, _ = generate_keypair()
    stranger = SigningKey(seed2).verify_key  # a different party's verify key
    cert["verify_key"] = base64.b64encode(bytes(stranger)).decode()
    assert not verify_certificate(cert)["ok"]


def test_certificate_needs_engine_receipts():
    sk, _ = generate_keypair()
    with pytest.raises(ValueError):
        issue_certificate(sk, subject_pseudonym="x" * 16,
                          request_ref_hash="a" * 64, engines=[],
                          ledger_head="b" * 64, ledger_entries=1,
                          operator="o", scope=[])


def test_certificate_carries_no_raw_subject():
    cert = _cert()
    blob = str(cert)
    assert "REQ-" not in blob  # raw request refs never enter the cert
    assert cert["body"]["subject_pseudonym"] == "ab12cd34ef56ab12"
