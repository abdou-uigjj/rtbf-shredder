"""the erasure-response lambda.

a data-subject request lands (api gateway or eventbridge). this handler
turns it into a signed erasure certificate: pseudonymize the request,
run every configured engine, append receipts to the ledger, sign the
certificate, return it. the signing key and the envelope master key are
injected via KMS at deploy time (terraform/ wires the permissions);
this handler never sees them as plaintext configuration.

event shape (kept boring on purpose):

    {
      "request_ref": "REQ-2026-000417",
      "target": {                      # deployment-specific paths
        "db": "/vault/clinic.db", "table": "patients",
        "columns": ["name", "notes"],
        "envelope_root": "/vault/envelopes",
        "aws_root": "/vault/aws", "bucket": "clinic-export"
      }
    }
"""

import base64
import json
import os
import secrets

from shredder.core import pseudonymize
from shredder.drivers.aws import AwsEngine
from shredder.drivers.local import LocalEngine
from shredder.drivers.sqlite_engine import SqliteEngine
from shredder.erase import ErasureTarget, erase_subject
from shredder.ledger import Ledger


class ErasureConfigError(RuntimeError):
    pass


def _b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s)


def handler(event, _context=None):
    try:
        request_ref = event["request_ref"]
        target = event["target"]
        salt = os.environ.get("RTBF_SALT", "")
        if not salt:
            raise ErasureConfigError("RTBF_SALT is not set")

        signing_key = _b64_to_bytes(os.environ.get("RTBF_SIGN_KEY_B64", ""))
        master_key = _b64_to_bytes(os.environ.get("RTBF_MASTER_KEY_B64", ""))
        if not signing_key or not master_key:
            raise ErasureConfigError("signing/master keys are not injected")

        sid = pseudonymize(request_ref, salt)
        markers = [f"RTBF-CANARY-{sid}"]  # deployments seed these at write time
        ledger = Ledger(os.environ.get("RTBF_LEDGER", "/vault/ledger.jsonl"))

        targets = []
        if target.get("db"):
            targets.append(ErasureTarget(
                SqliteEngine(target["db"]),
                table=target.get("table", "patients"),
                columns=target.get("columns", ["name", "notes"])))
        if target.get("envelope_root"):
            targets.append(ErasureTarget(
                LocalEngine(target["envelope_root"], master_key=master_key)))
        if target.get("aws_root"):
            aws = AwsEngine(target["aws_root"])
            if os.environ.get("RTBF_AWS_MODE") == AwsEngine.MODE_LIVE:
                aws.mode = AwsEngine.MODE_LIVE
            targets.append(ErasureTarget(aws, bucket=target.get(
                "bucket", "clinic-export")))

        if not targets:
            raise ErasureConfigError("no erasure targets configured")

        out = erase_subject(
            sid=sid, request_ref=request_ref, salt=salt, markers=markers,
            targets=targets, ledger=ledger, signing_key=signing_key,
            operator=os.environ.get("RTBF_OPERATOR", "rtbf-lambda"))

        return {
            "statusCode": 200,
            "body": json.dumps({
                "request_ref": request_ref,
                "subject_pseudonym": sid,
                "engines": [r["engine"] for r in out["receipts"]],
                "certificate": out["certificate"],
            }),
        }
    except (KeyError, ErasureConfigError, ValueError) as e:
        return {"statusCode": 400, "body": json.dumps({"error": str(e)})}
