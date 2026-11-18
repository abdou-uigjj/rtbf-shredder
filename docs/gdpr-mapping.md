# gdpr mapping

how rtbf-shredder's mechanisms map to the regulation's articles. this
is engineering documentation, not legal advice — your DPO owns the
legal interpretation; this page explains which mechanism serves which
requirement.

## article 17 — right to erasure

The core requirement: erase personal data "without undue delay". The
mechanism: `shredder.erase.erase_subject` runs all configured engines
in one call (sub-second for typical clinical workloads — the drill
completes the full three-engine erase in under a second) and issues
the signed certificate the controller can hand to the data subject.
The certificate is the "we did it, and here is what exactly was
erased" artifact that turns a verbal assurance into evidence.

**Article 17(2)** — informing other controllers about the erasure
request: the certificate is designed to be shared; it contains no raw
identities, so it can be sent to downstream processors without
leaking the subject to them.

**Article 17(3) exemptions** (legal obligation to retain, freedom of
expression, etc.): the tool does not decide scope — the operator
selects which engines and data classes participate. The certificate's
`scope` field records what was actually erased, which is what an
authority asks about when retention duties conflict with erasure.

## article 5(1)(e) — storage limitation

Data kept "no longer than necessary": the weekly sweep (CronJob /
eventbridge rule) enforces expiry-driven erasure, not just
request-driven. A record whose retention window ends is erased by the
same provable pipeline, with the same certificate trail.

## article 5(1)(f) / article 32 — integrity and security

- **32(1)(a) pseudonymization**: all artifacts are pseudonymous by
  construction (`shredder.core.pseudonymize`); the salt is a
  deployment secret.
- **32(1)(b) ongoing confidentiality**: envelope encryption at rest
  (per-record keys under a master key; in AWS, per-subject data keys
  under a KMS CMK).
- **32(1)(c) restoration after incident**: the DynamoDB ledger has
  point-in-time recovery; the hash chain makes silent edits detectable.
- **32(1)(d) regular testing**: the drill IS the test, and CI runs it
  on every push — the threat model's T1 (naive delete) is demonstrated
  empirically each run rather than asserted.

## article 20 — data portability (the interaction)

Erasure and portability interact: a subject may port their data and
then request erasure. The envelope store's `get` path is the
portability read (plaintext export under the subject's keys, before
any erasure); after erasure, `get` raises — the two lifecycle ends are
mechanically distinct, which prevents the classic bug of erasing a
record that has a pending portability request still in flight. Decide
the order in your request workflow; the tool enforces only that
erasure is final.

## article 33/34 — breach notification (adjacent)

The attacker module doubles as a breach-assessment tool: given a
suspected data-copy exposure (stolen backup, lost disk), run
`shredder.attacker.scan` over the recovered media image for the
canaries of every affected subject. Zero fragments means the stolen
copy carried no recoverable personal data — the difference between
"personal data breach" and "encrypted container stolen" for
notification purposes.

## recital 83-style documentation duty

Controllers must be able to demonstrate compliance. The signed
certificate + tamper-evident ledger + CI-verified drill are exactly
that demonstration: reproducible, offline-verifiable, and bound
together by hashes.
