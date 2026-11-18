# architecture

rtbf-shredder is built around one claim: **erasure is only real when
non-recovery is provable**. every component exists to either perform a
deletion or to attack that deletion and report what survived.

## components

**shredder/core.py** — pseudonymization and the sealed envelope store.
The data subject's identity never touches this tool: every directory
name, ledger entry and certificate carries a salted hash of the erasure
request reference. The envelope store seals each record under a
per-record key, wrapped by the deployment master key, so the plaintext
bytes never exist in the object store at all — only ciphertext.

**shredder/drivers/sqlite_engine.py** — surgical erasure for the
database. It locates the subject's rows by marker, overwrites each
target column in place with random bytes of the same length (so no
page is reallocated), deletes the rows, checkpoints and removes the
WAL/journal sidecars, rebuilds the database with `VACUUM INTO` and
atomically replaces the old file after mechanically shredding its
bytes. Every step is recorded in the receipt.

**shredder/drivers/local.py** — object-store erasure. Destroys every
wrapped record key (crypto-shred: the ciphertext becomes noise even if
a copy survives somewhere) and overwrites the box bytes themselves
(mechanical shred: nothing survives in the filesystem either).

**shredder/drivers/aws.py** — the KMS control plane. Per-subject data
keys are wrapped under a tenant CMK; erasure schedules the data key's
deletion and scrubs the subject's versioned objects. The simulation
runs offline with identical semantics; terraform/ deploys the live
path, lambda/ invokes it.

**shredder/attacker.py** — the recovery attacker. Raw byte pattern
search over the database file and every sidecar, and over directory
trees. It is deliberately dumb: if substring carving can recover a
subject's data, the erasure was fiction, whatever the schema says.

**shredder/ledger.py** — the hash-chained append-only ledger. Each
entry commits to the previous hash; `verify()` walks the whole chain.

**shredder/cert.py** — the signed erasure certificate (Ed25519),
binding subject pseudonym, engine receipts, scope and the ledger head
into a canonical JSON body. Verified offline by `tools/verify_cert.py`.

**drill/rtbf_drill.py** — the provable gate. Seeds three subjects,
runs the naive-delete trap, then the shredder, then attacks both, then
verifies the ledger and certificate. `PROOF HOLDS` requires all thirteen
assertions.

## data flow

```
art.17 request (request_ref)
        |
        v
pseudonymize(request_ref, salt) ──> sid
        |
        v
for each engine: erase_subject(sid) ──> receipt{recovery_before, recovery_after}
        |                                |
        v                                v
      bytes destroyed              ledger.append(receipt)
        |
        v
ledger head ──> issue_certificate(sk, receipts, head)
        |
        v
signed cert ──> data subject / DPO (verify offline)
```

## what is NOT in scope

Key rotation of the tenant CMK, backup-target shredding (backups are
covered by the crypto-shred argument: their ciphertext dies with the
data key), and live KMS integration tests — the terraform module and
lambda define the real path; CI exercises the same semantics offline.
