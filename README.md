# rtbf-shredder

**Provable right-to-be-forgotten erasure.** When a data subject sends
an art. 17 request, this tool erases them from every storage engine —
and then attacks its own erasure with a byte-level recovery tool and
publishes the signed evidence that nothing was recoverable.

We do not claim deletion. We prove non-recovery.

## why "deleted" is not "erased"

```
$ python3 drill/rtbf_drill.py
== world 1: naive delete (the trap) ==
  PASS  naive-delete-recoverable     attacker recovered 15 fragments (615 bytes) after plain DELETE
== world 2: shredder erasure of subject b ==
  PASS  sqlite-recovery-zero         attacker found 0 fragments in db + sidecars (0.01s)
  PASS  envelope-crypto-shred        plaintext never touched disk (sealed); keys + boxes now destroyed
  PASS  aws-crypto-shred             wrapped data key destroyed; 3 chart versions scrubbed from the bucket
  PASS  surgical-others-intact       subjects a and c: 80/80 rows untouched
== world 3: ledger and certificate ==
  PASS  ledger-chain-valid           4 entries, head 2abfac369a0b...
  PASS  certificate-valid            ed25519 signature ok (868ba20a...)
== verdict: PROOF HOLDS (13 passed, 0 failed) ==
```

A plain `DELETE FROM` leaves the subject's bytes in freelist pages and
the WAL — the drill's recovery attacker pulls them out of the raw file
in milliseconds. The shredder erases the same subject surgically:
payload overwritten in place, rows deleted, sidecars removed, database
rebuilt, envelope keys destroyed, KMS data key scheduled for deletion.
The attacker comes back empty. The other subjects are untouched —
surgical, not scorched earth.

## the pieces

| component | what it does |
| --- | --- |
| `shredder/drivers/sqlite_engine.py` | surgical db erasure: overwrite → delete → checkpoint → vacuum-rebuild → shred old file |
| `shredder/drivers/local.py` | envelope crypto-shred + mechanical byte-shred for the object store |
| `shredder/drivers/aws.py` | KMS cryptographic erasure: destroy the per-subject data key, scrub versions (simulated offline, live via lambda) |
| `shredder/attacker.py` | the recovery attacker: raw byte carving over db + sidecars + trees |
| `shredder/ledger.py` | append-only hash-chained ledger of every erasure receipt |
| `shredder/cert.py` | ed25519-signed erasure certificate bound to the ledger head |
| `drill/rtbf_drill.py` | the provable gate: 13 assertions or `PROOF FAILS` |
| `tools/verify_cert.py` | what the data subject runs to check their receipt |

## quickstart

```bash
pip install -r requirements.txt
python3 drill/rtbf_drill.py --keep          # the provable gate
python3 -m pytest tests/ -q                 # 38 unit tests
python3 tools/verify_ledger.py /tmp/rtbf-drill-*/ledger.jsonl
```

## quickstart: an erasure request

```python
from shredder.erase import erase_subject, ErasureTarget
from shredder.drivers.sqlite_engine import SqliteEngine
from shredder.drivers.local import LocalEngine
from shredder.drivers.aws import AwsEngine
from shredder.ledger import Ledger

out = erase_subject(
    sid=sid, request_ref="REQ-2026-000417", salt=salt,
    markers=[canary_marker],
    targets=[
        ErasureTarget(SqliteEngine("/vault/clinic.db"),
                      table="patients", columns=["name", "notes"]),
        ErasureTarget(LocalEngine("/vault/envelopes", master_key=master)),
        ErasureTarget(AwsEngine("/vault/aws"), bucket="clinic-export"),
    ],
    ledger=ledger, signing_key=sk, operator="clinic-dpo")
# out["certificate"] - signed, pseudonymous, offline-verifiable
```

## deployment

- `terraform/` — KMS operator CMK, versioned + KMS-sealed bucket,
  DynamoDB ledger with PITR, the erasure lambda with a
  least-privilege role and a weekly sweep.
- `lambda/` — the request responder: pseudonymize, erase, ledger,
  sign, return the certificate.
- `k8s/` — the weekly sweep cronjob, hardened (non-root, read-only
  root, no k8s api access, default-deny netpol) and policed by the
  conftest pack in `policy/` (175 assertions, negative fixtures in
  `examples/policy-negative/` must fail).

## documentation

- [docs/architecture.md](docs/architecture.md) — the components and data flow
- [docs/threat-model.md](docs/threat-model.md) — the five threats and what answers them
- [docs/provable-gate.md](docs/provable-gate.md) — how "we erased it" becomes evidence
- [docs/runbook-erasure.md](docs/runbook-erasure.md) — operating an art. 17 request end to end
- [docs/gdpr-mapping.md](docs/gdpr-mapping.md) — mechanisms to articles

## license

MIT — see LICENSE.
