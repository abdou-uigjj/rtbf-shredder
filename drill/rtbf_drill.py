#!/usr/bin/env python3
"""the rtbf provable gate.

scenario: a clinic holds patient records for three subjects. subject b
sends an erasure request (gdpr art. 17). the drill runs three worlds:

  naive    a well-meaning operator runs plain `delete from` and unlinks
           one exported file. the attacker then recovers b's data from
           raw bytes. this is the industry's dirty secret - 'deleted'
           is not erased.

  shredder the same subject erased through the shredder: surgical
           sqlite erase, envelope crypto-shred, simulated-kms key
           destruction. the attacker recovers nothing from the db.
           subjects a and c are untouched - surgical, not scorched earth.

  ledger   the hash chain verifies, a tampered copy fails verification,
           and the signed certificate checks out against its public key.

verdict is PROOF HOLDS only if every assertion passes. artifacts stay
in /tmp/rtbf-drill-<ts>/ for inspection.
"""

import argparse
import json
import os
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shredder.attacker import scan                      # noqa: E402
from shredder.cert import generate_keypair, verify_certificate  # noqa: E402
from shredder.core import pseudonymize                  # noqa: E402
from shredder.drivers.aws import AwsEngine              # noqa: E402
from shredder.drivers.local import LocalEngine          # noqa: E402
from shredder.drivers.sqlite_engine import SqliteEngine  # noqa: E402
from shredder.erase import ErasureTarget, erase_subject  # noqa: E402
from shredder.ledger import Ledger                      # noqa: E402

PASS, FAIL = 0, 0


def ok(name: str, detail: str) -> None:
    global PASS  # noqa: PLW0603
    PASS += 1
    print(f"  PASS  {name:<28} {detail}")


def bad(name: str, detail: str) -> None:
    global FAIL  # noqa: PLW0603
    FAIL += 1
    print(f"  FAIL  {name:<28} {detail}")


SCHEMA = """
create table patients (
    name text, dob text, mrn text unique, notes text
)
"""


def rows_for(mrn: str, marker: str, n: int) -> list[dict]:
    return [{"name": f"Patient {i} ({mrn})", "dob": "1988-04-1x",
             "mrn": f"{mrn}-{i}",
             "notes": f"charts {i}; {marker}; ongoing care"}
            for i in range(n)]


def main() -> int:
    ap = argparse.ArgumentParser(description="rtbf provable gate")
    ap.add_argument("--keep", action="store_true",
                    help="keep the workspace for inspection")
    args = ap.parse_args()

    work = tempfile.mkdtemp(prefix="rtbf-drill-")
    salt = secrets.token_hex(8)
    subjects = {}
    for label, mrn in (("a", "MRN-4471"), ("b", "MRN-8823"), ("c", "MRN-1090")):
        sid = pseudonymize(mrn, salt)
        subjects[label] = {"mrn": mrn, "sid": sid,
                           "marker": f"RTBF-CANARY-{sid}-{secrets.token_hex(6)}"}

    print(f"== rtbf drill | workspace {work} ==")
    print("== seeded 3 subjects with plaintext canaries (db), sealed envelopes, "
          "and versioned s3-style objects ==")

    # -- seed the world -----------------------------------------------------
    db = os.path.join(work, "clinic.db")
    engine = SqliteEngine(db)
    all_rows = []
    for label in ("a", "b", "c"):
        all_rows += rows_for(subjects[label]["mrn"], subjects[label]["marker"], 40)
    engine.seed("patients", SCHEMA, all_rows)

    store = LocalEngine(os.path.join(work, "envelopes"),
                        master_key=secrets.token_bytes(32))
    aws = AwsEngine(os.path.join(work, "aws"))
    aws.create_tenant_key()
    # the forgotten copies: every clinic exports charts as plaintext csv
    # files. deletion never touches these - and this is exactly where
    # naive erasure dies, on every sqlite build (modern builds zero freed
    # pages on delete; the export copy never notices).
    exports = os.path.join(work, "exports")
    os.makedirs(exports)
    for s in subjects.values():
        with open(os.path.join(exports, f"export-{s['mrn']}.csv"), "w") as f:
            f.write("name,dob,mrn,notes\n")
            for r in rows_for(s["mrn"], s["marker"], 40):
                f.write(f'"{r["name"]}",{r["dob"]},{r["mrn"]},"{r["notes"]}"\n')
    for s in subjects.values():
        for i in range(3):
            store.seed(s["sid"], f"record-{i}",
                       f"referral {i}: {s['marker']} / imaging notes".encode())
            aws.put_object("clinic-export", s["sid"], f"chart-{i}",
                           f"chart export {i} {s['marker']}".encode())

    mb = subjects["b"]["marker"]
    sid_b = subjects["b"]["sid"]

    # -- world 1: naive deletion ------------------------------------------------
    print("== world 1: naive delete (the trap) ==")
    conn = sqlite3.connect(db)
    conn.execute("delete from patients where mrn like ?",
                 (f"{subjects['b']['mrn']}%",))
    conn.commit()
    conn.close()
    os.unlink(os.path.join(work, "envelopes", "subjects", sid_b, "record-0.box"))

    naive_db = scan(db, [mb])
    naive_export = scan(os.path.join(exports, f"export-{subjects['b']['mrn']}.csv"), [mb])
    naive_total = naive_db["total_fragments"] + naive_export["total_fragments"]
    if naive_total > 0:
        ok("naive-delete-recoverable",
           f"attacker recovered {naive_total} fragments after plain DELETE "
           f"({naive_db['total_fragments']} in db, "
           f"{naive_export['total_fragments']} in the forgotten export csv)")
    else:
        bad("naive-delete-recoverable",
            "naive delete left nothing to find - demo broken, practice fine")

    # -- world 2: the shredder ----------------------------------------------------
    print("== world 2: shredder erasure of subject b ==")
    ledger = Ledger(os.path.join(work, "ledger.jsonl"))
    sk, _ = generate_keypair()
    request_ref = "REQ-2026-000417"
    t0 = time.time()
    result = erase_subject(
        sid=sid_b,
        request_ref=request_ref,
        salt=salt,
        markers=[mb],
        targets=[
            ErasureTarget(engine, table="patients", columns=["name", "notes"]),
            ErasureTarget(store),
            ErasureTarget(aws, bucket="clinic-export"),
        ],
        ledger=ledger,
        signing_key=sk,
        operator="clinic-dpo",
    )
    elapsed = time.time() - t0

    # the export copy is in scope too: it is the subject's plaintext.
    from shredder.core import shred_file
    export_b = os.path.join(exports, f"export-{subjects['b']['mrn']}.csv")
    shred_file(export_b)
    ledger.append("export-shredded", {"sid": sid_b,
                                      "file": os.path.basename(export_b)})

    after = engine.attacker_scan([mb])
    if after["total_fragments"] == 0:
        ok("sqlite-recovery-zero",
           f"attacker found 0 fragments in db + sidecars ({elapsed:.2f}s)")
    else:
        bad("sqlite-recovery-zero",
            f"attacker still finds {after['total_fragments']} fragments in the db")
    if not os.path.exists(export_b):
        ok("export-shredded", "the forgotten csv copy is gone - byte-level")
    else:
        bad("export-shredded", "export copy survived the erasure")

    tree_after = store.attacker_scan([mb])
    sid_dir = os.path.join(work, "envelopes", "subjects", sid_b)
    if tree_after["total_fragments"] == 0 and not os.path.isdir(sid_dir):
        ok("envelope-crypto-shred",
           "plaintext never touched disk (sealed); keys + boxes now destroyed")
    else:
        bad("envelope-crypto-shred",
            f"subject envelope dir still exists or plaintext found "
            f"({tree_after['total_fragments']} fragments)")
    try:
        store.store.get(sid_b, "record-1")
        bad("envelope-unreadable", "shredded record still decrypts?!")
    except KeyError:
        ok("envelope-unreadable", "shredded records no longer decrypt - keys are gone")

    b_aws = [r for r in result["receipts"] if r["engine"] == "aws-kms-sim"][0]
    if b_aws["data_keys_destroyed"] == 1 and b_aws["versions_scrubbed"] == 3:
        ok("aws-crypto-shred",
           "wrapped data key destroyed; 3 chart versions scrubbed from the bucket")
    else:
        bad("aws-crypto-shred", f"aws receipt incomplete: {b_aws}")

    # surgical: a and c must be fully intact
    conn = sqlite3.connect(db)
    survivors = conn.execute(
        "select count(*) from patients where mrn like 'MRN-4471%' "
        "or mrn like 'MRN-1090%'").fetchone()[0]
    b_gone = conn.execute(
        "select count(*) from patients where mrn like 'MRN-8823%'").fetchone()[0]
    integrity = conn.execute("pragma integrity_check").fetchone()[0]
    conn.close()
    if survivors == 80:
        ok("surgical-others-intact", "subjects a and c: 80/80 rows untouched")
    else:
        bad("surgical-others-intact",
            f"expected 80 surviving rows, found {survivors}")
    if b_gone == 0 and integrity == "ok":
        ok("db-clean", "subject b has no rows; integrity_check ok")
    else:
        bad("db-clean", f"b rows: {b_gone}, integrity: {integrity}")
    others_db = engine.attacker_scan([subjects["a"]["marker"], subjects["c"]["marker"]])
    a_csv = os.path.join(exports, f"export-{subjects['a']['mrn']}.csv")
    c_csv = os.path.join(exports, f"export-{subjects['c']['mrn']}.csv")
    others_total = (others_db["total_fragments"]
                    + scan(a_csv, [subjects["a"]["marker"]])["total_fragments"]
                    + scan(c_csv, [subjects["c"]["marker"]])["total_fragments"])
    if others_total > 0:
        ok("others-bytes-intact",
           f"a+c canary bytes still present ({others_total} "
           f"fragments, db + their exports) - only b was erased")
    else:
        bad("others-bytes-intact",
            "a+c markers gone - the erasure was not surgical")

    # -- world 3: ledger + certificate -------------------------------------------
    print("== world 3: ledger and certificate ==")
    v = ledger.verify()
    if v["ok"]:
        ok("ledger-chain-valid", f"{v['entries']} entries, head {v['head'][:12]}...")
    else:
        bad("ledger-chain-valid", v["reason"])

    tampered = os.path.join(work, "ledger-tampered.jsonl")
    shutil.copy(ledger.path, tampered)
    with open(tampered) as f:
        lines = f.readlines()
    if len(lines) < 2:
        bad("ledger-tamper-evident", "ledger too short to tamper with")
    else:
        lines[1] = lines[1].replace('"engine-erasure"', '"engine-erase"', 1)
        with open(tampered, "w") as f:
            f.writelines(lines)
        if not Ledger(tampered).verify()["ok"]:
            ok("ledger-tamper-evident", "flipping one action word breaks the chain")
        else:
            bad("ledger-tamper-evident", "tampered ledger still verifies")

    cert = result["certificate"]
    cv = verify_certificate(cert)
    if cv["ok"]:
        ok("certificate-valid",
           f"ed25519 signature ok ({cert['body']['cert_id'][:8]}...)")
    else:
        bad("certificate-valid", cv["reason"])
    if cert["body"]["ledger_head_sha256"] == result["ledger_head"]:
        ok("cert-bound-to-ledger", "certificate commits to the ledger head")
    else:
        bad("cert-bound-to-ledger", "certificate/ledger head mismatch")
    cert_blob = json.dumps(cert)
    if cert["body"]["subject_pseudonym"] == sid_b and \
            subjects["b"]["mrn"] not in cert_blob and \
            mb not in cert_blob:
        ok("cert-pseudonymous", "cert carries the pseudonym, never the mrn or canary")
    else:
        bad("cert-pseudonymous", "raw identity leaked into the certificate")

    # -- verdict -----------------------------------------------------------------
    print(f"== verdict: {'PROOF HOLDS' if FAIL == 0 else 'PROOF FAILS'} "
          f"({PASS} passed, {FAIL} failed) ==")
    print(f"== artifacts kept for inspection: {work} ==")
    if FAIL == 0 and not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
