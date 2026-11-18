RTBF-SHREDDER CHANGELOG
=======================

v1.0.0 - 2026-11-18
-------------------
first release.

* envelope store: per-record keys under a deployment master key,
  pseudonymous by construction (salted hash directory names).
* sqlite surgical engine: in-place payload overwrite, wal/journal
  removal, vacuum-into rebuild, old-file shred. integrity-checked.
* local engine: crypto-shred (key destruction) + mechanical shred.
* aws engine: simulated kms control plane with live-path semantics -
  wrapped per-subject data keys, versioned objects, crypto-shred on
  erasure. terraform deploys the real one.
* recovery attacker: raw byte carving over db + sidecars + trees.
* erasure ledger: append-only hash chain, tamper-evident, verified
  offline by tools/verify_ledger.py.
* erasure certificate: ed25519-signed, bound to the ledger head,
  carries pseudonyms only, verified offline by tools/verify_cert.py.
* drill: the provable gate - naive-delete trap, shredder erasure,
  surgical check, ledger tamper test, certificate check. 13 assertions.
* lambda responder + terraform pipeline (kms, s3, dynamodb, iam,
  weekly sweep, error alarm).
* k8s cronjob sweep with conftest policy pack (175 assertions) and
  negative fixtures that must be rejected.
* tests: 38 unit tests.
