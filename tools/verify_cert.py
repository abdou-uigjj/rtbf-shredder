"""offline verifiers: what a data subject or auditor runs with nothing
but the public key and the exported artifacts. no dependencies beyond
pynacl, no network, no trust in the operator's database."""

import argparse
import base64
import json
import sys

sys.path.insert(0, ".")

from shredder.cert import verify_certificate        # noqa: E402
from shredder.ledger import Ledger                  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="verify an erasure certificate")
    ap.add_argument("cert", help="certificate json file")
    args = ap.parse_args()
    with open(args.cert) as f:
        cert = json.load(f)
    result = verify_certificate(cert)
    body = cert.get("body", {})
    print(f"certificate : {body.get('cert_id', '?')}")
    print(f"issued at   : {body.get('issued_at', '?')}")
    print(f"operator    : {body.get('operator', '?')}")
    print(f"subject     : {body.get('subject_pseudonym', '?')} (pseudonym)")
    print(f"ledger head : {body.get('ledger_head_sha256', '?')[:16]}...")
    print(f"engines     : {', '.join(body.get('scope', []))}")
    print(f"signature   : {'VALID' if result['ok'] else 'INVALID'}"
          + ("" if result["ok"] else f" ({result['reason']})"))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
