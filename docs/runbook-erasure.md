# runbook: handling an art. 17 erasure request

## before any request arrives (deployment-time)

1. **generate the signing key** and keep the seed in your secret store:
   `python3 -c "from shredder.cert import generate_keypair; import base64; sk,vk=generate_keypair(); print(base64.b64encode(sk).decode())"`.
   The verify key is public — embed it in `tools/verify_cert.py` calls
   or publish it to data subjects.
2. **set the deployment salt** (`RTBF_SALT`): `openssl rand -hex 16`.
   Losing the salt means losing the pseudonym mapping, so store it with
   the same care as the signing key.
3. **inject at runtime, never in manifests**: `RTBF_SIGN_KEY_B64`,
   `RTBF_MASTER_KEY_B64`, `RTBF_SALT` come from your secret manager
   (terraform wires this for the lambda). The conftest policy pack
   rejects any Secret manifest in k8s/ for exactly this reason.
4. **seed canaries at write time**: every record gets
   `RTBF-CANARY-<sid>-<random>` inside a representative field. Without
   canaries, erasure cannot be proven after the fact.

## when a request arrives (per-subject)

1. **log the request** in your records (identity of requester, date,
   scope). This mapping is deliberately outside the tool.
2. **invoke the erasure**. Lambda path: send the event from
   `lambda/handler.py`'s docstring to the responder function. CLI path
   (small deployments): call `shredder.erase.erase_subject` with the
   same arguments the drill uses, against your real paths.
3. **check the receipts**. Every engine's receipt must show
   `recovery_after.fragments == 0`. A non-zero number means the erase
   is incomplete — do not issue a certificate; investigate with the
   recovery attacker directly.
4. **export the artifacts**: the ledger (`jsonl`) and the certificate
   (json). The certificate goes to the data subject; both go to your
   compliance archive.
5. **verify like a stranger**: `python3 tools/verify_cert.py cert.json`
   and `python3 tools/verify_ledger.py ledger.jsonl`. Both must pass
   with no arguments beyond the files. If you cannot verify your own
   receipt offline, neither can an auditor.

## when something looks wrong

- **`surgical-others-intact` fails**: stop. You just erased the wrong
  scope. Check the pseudonym mapping and the marker uniqueness before
  any further erasure. Restore from the most recent backup if needed.
- **`ledger-chain-valid` fails on a historical export**: treat the
  archive as compromised. Compare with the DynamoDB ledger (PITR) and
  investigate who wrote the diverging line.
- **a subject's data reappears after erasure** (T3 in the threat
  model): the weekly sweep fires. Find the restore path that revived
  it, re-run the erasure, and issue a fresh certificate referencing the
  new ledger entries.

## after the fact

Data subjects get: the certificate. Auditors get: the certificate plus
the ledger export for the period. Nobody gets: the salt, the signing
key, or the pseudonym mapping.
