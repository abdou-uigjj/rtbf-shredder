# threat model

## what this tool defends against

**T1 — the optimistic operator.** A developer runs `delete from patients
where mrn = ?`, considers the job done, and the bytes live on in
freelist pages, the WAL, and every backup taken since. *Mitigation:* the
drill's naive-delete trap demonstrates recovery on the exact database
shape production uses, and the erasure certificate can only be issued by
engines whose receipts show `recovery_after.fragments == 0`.

**T2 — the forensic attacker with disk access.** Someone gets a copy of
the storage (stolen backup, decommissioned disk, compromised replica)
and runs byte carving. *Mitigation:* two independent layers. Crypto: all
subject data is sealed under per-record keys destroyed at erasure; the
carver finds ciphertext whose keys no longer exist. Mechanical: the
bytes themselves are overwritten and the database rebuilt, so nothing
carvable remains even in principle.

**T3 — the silent rollback.** Weeks later, someone "restores" the
erased subject's data from an old backup, undoing the erasure without
anyone noticing. *Mitigation:* the hash-chained ledger records the
erasure; the weekly sweep (CronJob, eventbridge rate rule) re-checks
that erased subjects stay erased, and the DynamoDB ledger's PITR makes
"losing" entries an alarmable event.

**T4 — the forged receipt.** A pressured operator issues a certificate
without actually erasing anything. *Mitigation:* certificates are
Ed25519-signed by an operator key whose private half exists only in the
signing enclave; the certificate commits to the ledger head at issuance,
so the claimed engines' receipts must exist in the chain — and the
ledger itself is tamper-evident, so back-filling a receipt changes the
head and invalidates the certificate.

**T5 — correlation of erasure requests.** An attacker who can read the
ledger or certificates wants to know which real people requested
erasure. *Mitigation:* everything carries only salted pseudonyms
(`sha256(salt:request_ref)[:16]`); the salt lives in the deployment's
secret store and never in this tool. Certificates are safe to hand to
the data subject and safe to show an auditor without deanonymizing
anyone else.

## what this tool does NOT defend against

- **Compromised operator key or salt.** Whoever holds the signing key
  can forge certificates; whoever holds the salt can re-identify
  pseudonyms. These are the operator's crown jewels (terraform injects
  them from KMS).
- **Storage media that ignore overwrites.** Wear-leveled flash (SSDs,
  NVMe) remaps writes, so mechanical overwrite is best-effort there.
  The crypto-shred layer is the one that actually matters on such
  media — which is why erasure never relies on the overwrite alone.
- **Pre-erasure exfiltration.** If the attacker already copied the
  plaintext while it was live, erasure cannot retroactively help. The
  sealed envelope store narrows this window (plaintext only exists
  inside a container's memory and the receiving engine), not eliminate it.
- **Ledger denial of service.** The ledger is append-only but lives on
  operator-controlled storage; a hostile operator can delete it whole.
  PITR on the DynamoDB backend is the production answer; the local
  jsonl export is for drills and small deployments.

## assumptions

The operator's KMS is honest. The host running the drill or lambda is
not memory-forensics-compromised at the moment keys are in memory.
The salt and signing key are never written to disk. These are standard
assumptions for the deployment tier this tool targets.
