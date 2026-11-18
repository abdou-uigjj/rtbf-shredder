# the provable gate

most erasure tooling stops at "we ran the delete and it returned
successfully." rtbf-shredder refuses to accept that as erasure. the
provable gate is the mechanism that turns deletion into evidence.

## the three-step claim

**step 1 — canary.** every subject's data carries an embedded canary:
a unique byte marker (`RTBF-CANARY-<sid>-<random>`) planted at write
time inside representative fields. the canary is not metadata — it
lives inside the values themselves, so any copy that preserves the
data preserves the canary, and any operation that truly destroys the
data destroys the canary.

**step 2 — attack.** the recovery attacker (`shredder/attacker.py`)
scans raw bytes the way a forensic tool would: no schema, no queries,
no cooperation from the database engine. it reads the database file,
every sqlite sidecar (`-wal`, `-shm`, `-journal`), or walks a whole
directory tree, and counts occurrences of each canary. the scan is
deterministic and cheap, which is what makes it CI-able.

**step 3 — verdict.** an erasure is accepted only when the same scan
that recovered data before the erase recovers zero bytes after it,
*and* every other subject's canaries are still present (surgical
proof), *and* the ledger chain verifies, *and* the certificate
signature checks out. the drill prints `PROOF HOLDS` only when all of
those hold, and exits non-zero otherwise.

## what the drill shows

the drill runs the naive-delete world first, on purpose. a plain
`delete from patients where ...` leaves the subject's bytes
recoverable — in the drill's workspace the attacker typically pulls
hundreds of bytes of canary fragments out of the file after a
"successful" delete. that number is the whole argument: the industry's
default erasure is recoverable with a one-line byte scan.

the shredder world then erases the same subject through the engines.
the attacker finds nothing. the other two subjects' canary bytes are
still exactly where they were, proving the erasure was surgical. the
database passes `integrity_check`. no sidecars survive. the envelope
store's subject directory is gone entirely, and a previously readable
record no longer decrypts — the keys are gone.

the ledger world closes the loop: the chain verifies, a tampered copy
(one edited action word) fails verification, the certificate verifies
against its public key, and the certificate's `ledger_head_sha256`
matches the chain it claims to summarize.

## running it

```
python3 drill/rtbf_drill.py [--keep]
```

`--keep` preserves `/tmp/rtbf-drill-<ts>/` for manual inspection —
open the database in a sqlite shell, hexdump the envelope directory,
run `tools/verify_ledger.py` on the exported chain.

## interpreting failure

each assertion names the property it guards. if
`naive-delete-recoverable` fails, the demo's seeding broke (nothing to
learn). if `sqlite-recovery-zero` fails, the engine has a real bug —
file it with the drill's `--keep` workspace attached. if
`ledger-tamper-evident` fails, stop and audit every ledger export you
have ever issued.
