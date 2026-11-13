"""the erasure certificate: a signed receipt a data subject can hold.

the certificate states who erased what, with which engines, against
which ledger head - and the operator signs it with an ed25519 key. the
data subject (or a DPO, or a supervisory authority) can verify the
signature offline with nothing but the public key: `tools/verify_cert.py`.

privacy note: the certificate carries the subject pseudonym, never the
raw identity. it is itself personal-data-safe: you can publish a
certificate without exposing who requested erasure.
"""

import base64
import hashlib
import json
import time
import uuid

from nacl.signing import SigningKey, VerifyKey

CERT_VERSION = 1


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def generate_keypair() -> tuple[bytes, bytes]:
    """returns (seed, verify_bytes). the seed is the operator's private key;
    publish the verify key (it is what tools/verify_cert.py embeds)."""
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def issue_certificate(
    signing_key_seed: bytes,
    *,
    subject_pseudonym: str,
    request_ref_hash: str,
    engines: list[dict],
    ledger_head: str,
    ledger_entries: int,
    operator: str,
    scope: list[str],
) -> dict:
    """sign the canonical certificate body and return the full cert."""
    if not engines:
        raise ValueError("a certificate with no engine receipts attests to nothing")
    body = {
        "version": CERT_VERSION,
        "cert_id": str(uuid.uuid4()),
        "issued_at": _now(),
        "operator": operator,
        "subject_pseudonym": subject_pseudonym,
        "request_ref_hash": request_ref_hash,
        "scope": sorted(scope),
        "engines": engines,
        "ledger_head_sha256": ledger_head,
        "ledger_entries": ledger_entries,
    }
    body_bytes = _canonical(body)
    digest = hashlib.sha256(body_bytes).digest()
    sk = SigningKey(signing_key_seed)
    sig = sk.sign(digest).signature
    return {
        "body": body,
        "signature": base64.b64encode(sig).decode(),
        "signed_sha256": digest.hex(),
        "verify_key": base64.b64encode(bytes(sk.verify_key)).decode(),
    }


def verify_certificate(cert: dict) -> dict:
    """recompute the canonical body, re-hash, verify the ed25519 signature.

    returns {ok, reason}. never trusts cert['signed_sha256'] - it is
    recomputed from the body so that a tampered body always fails."""
    try:
        body = cert["body"]
        sig = base64.b64decode(cert["signature"])
        vk = VerifyKey(base64.b64decode(cert["verify_key"]))
        digest = hashlib.sha256(_canonical(body)).digest()
        vk.verify(digest, sig)
        stated = cert.get("signed_sha256")
        if stated and stated != digest.hex():
            return {"ok": False,
                    "reason": "body hash does not match the stated signed_sha256"}
        return {"ok": True, "reason": "signature valid", "cert_id": body.get("cert_id")}
    except Exception as e:  # noqa: BLE001 - verification must never raise
        return {"ok": False, "reason": f"verification failed: {e}"}
