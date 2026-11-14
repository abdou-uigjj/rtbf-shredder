"""local filesystem erasure: crypto-shred + mechanical shred.

the envelope store holds every subject's data sealed under per-record
keys. erasure here is therefore two-handed and both hands are verified:

  - destroy every wrapped record key (the ciphertext becomes noise)
  - overwrite the ciphertext bytes themselves (belt over braces)
  - remove metadata and prune the pseudonymous subject directory

the receipt records exactly how many bytes died. the attacker then
walks the store tree hunting markers; after this driver runs, there is
nothing left to find.
"""

import os

from ..core import EnvelopeStore
from ..attacker import scan_tree


class LocalEngine:
    def __init__(self, store_root: str, master_key: bytes | None = None):
        self.store = EnvelopeStore(store_root, master_key=master_key)

    def seed(self, sid: str, rid: str, data: bytes) -> dict:
        return self.store.put(sid, rid, data)

    def attacker_scan(self, markers: list[str]) -> dict:
        return scan_tree(self.store.subjects, markers)

    def erase_subject(self, sid: str, markers: list[str]) -> dict:
        before = self.attacker_scan(markers)
        receipt = self.store.shred_subject(sid)
        after = self.attacker_scan(markers)
        return {
            "engine": "local-envelope",
            "store_root": os.path.basename(self.store.root),
            "records_shredded": receipt["records_shredded"],
            "bytes_shredded": receipt["bytes_shredded"],
            "recovery_before": {"fragments": before["total_fragments"],
                                "bytes": before["total_bytes_recoverable"]},
            "recovery_after": {"fragments": after["total_fragments"],
                               "bytes": after["total_bytes_recoverable"]},
        }
