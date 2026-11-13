"""core: pseudonymization + the sealed envelope store.

two rules drive everything here:

1. the data subject's identity never appears on disk. every artifact -
   directory names, ledger entries, certificates - carries only the
   pseudonym, a salted hash of the request reference. the mapping from
   pseudonym back to person lives in the operator's own records (the
   erasure request they received), nowhere in this tool.

2. erasure is two-handed: destroy the keys (crypto-shred) AND overwrite
   the bytes (mechanical shred). either alone leaves a gap - a copied
   ciphertext without keys is inert, but operators and auditors think in
   terms of bytes, so we do both, and the recovery attacker checks the
   result.
"""

import hashlib
import json
import os
import secrets
import shutil
import stat
import time

from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

MASTER_MODE = 0o600


def pseudonymize(request_ref: str, salt: str) -> str:
    """salted hash of the erasure request reference.

    the salt is a per-deployment secret (env RTBF_SALT in production).
    without it, an attacker with a list of candidate request refs could
    confirm which subjects appear in the ledger by rehashing them. with
    it, the ledger and certificates are anonymous by construction.
    """
    if not salt:
        raise ValueError("RTBF_SALT must not be empty - unsalted pseudonyms can be brute-forced")
    h = hashlib.sha256(f"{salt}:{request_ref}".encode()).hexdigest()
    return h[:16]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def shred_file(path: str, passes: int = 2) -> int:
    """overwrite a file's bytes pass by pass, then unlink it.

    pass 1 random, pass 2 zeros. returns the number of bytes shredded.
    we fsync after every pass so the overwrite actually reaches the
    medium before the unlink; without that, a crash could leave the
    original bytes on disk with only the directory entry gone.
    """
    size = os.path.getsize(path)
    if size == 0:
        os.unlink(path)
        return 0
    patterns = [os.urandom(size)] + [b"\x00" * size for _ in range(passes - 1)]
    with open(path, "r+b") as f:
        for blob in patterns:
            f.seek(0)
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
    os.unlink(path)
    return size


class MasterKeyError(RuntimeError):
    pass


class EnvelopeStore:
    """per-subject sealed envelopes under a master key.

    layout (all names pseudonymous):

        root/master.key                     SecretBox key, 0o600
        root/subjects/<sid>/meta.json       record index, no raw ids
        root/subjects/<sid>/<rid>.key       record key, wrapped by master
        root/subjects/<sid>/<rid>.box       ciphertext, sealed with record key

    shredding a record destroys its wrapped key, overwrites the box
    bytes, removes both files and prunes the subject directory. the
    payload bytes are unrecoverable twice over: without the record key
    the ciphertext is noise, and after the overwrite the ciphertext
    itself is gone.
    """

    def __init__(self, root: str, master_key: bytes | None = None):
        self.root = os.path.abspath(root)
        self.subjects = os.path.join(self.root, "subjects")
        os.makedirs(self.subjects, exist_ok=True)
        self._master_path = os.path.join(self.root, "master.key")
        if master_key is not None:
            self._write_master(master_key)
        self._master = self._load_master()

    # -- master key ----------------------------------------------------
    def _write_master(self, key: bytes) -> None:
        if len(key) != SecretBox.KEY_SIZE:
            raise MasterKeyError(f"master key must be {SecretBox.KEY_SIZE} bytes")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(self._master_path, flags, MASTER_MODE)
        try:
            os.write(fd, key)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(self.root)

    def _load_master(self) -> bytes:
        try:
            with open(self._master_path, "rb") as f:
                key = f.read()
        except FileNotFoundError as e:
            raise MasterKeyError(
                "no master key - create one or pass master_key= to the store"
            ) from e
        mode = stat.S_IMODE(os.stat(self._master_path).st_mode)
        if mode & 0o077:
            raise MasterKeyError(f"master.key is mode {oct(mode)} - must be 0o600")
        return key

    # -- paths ----------------------------------------------------------
    def _subject_dir(self, sid: str) -> str:
        return os.path.join(self.subjects, sid)

    def _record_paths(self, sid: str, rid: str) -> tuple[str, str]:
        d = self._subject_dir(sid)
        return os.path.join(d, f"{rid}.key"), os.path.join(d, f"{rid}.box")

    # -- write / read ----------------------------------------------------
    def put(self, sid: str, rid: str, data: bytes) -> dict:
        d = self._subject_dir(sid)
        os.makedirs(d, mode=0o700, exist_ok=True)
        key_path, box_path = self._record_paths(sid, rid)

        record_key = secrets.token_bytes(SecretBox.KEY_SIZE)
        wrapped = SecretBox(self._master).encrypt(record_key)
        sealed = SecretBox(record_key).encrypt(data)

        for path, blob in ((key_path, wrapped), (box_path, sealed)):
            with open(path, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(path, 0o600)
        _fsync_dir(d)

        meta_path = os.path.join(d, "meta.json")
        meta = {}
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
        meta.setdefault("records", []).append(
            {"rid": rid, "bytes": len(data), "stored_at": _now()}
        )
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=1)
        return {"sid": sid, "rid": rid, "bytes": len(data)}

    def get(self, sid: str, rid: str) -> bytes:
        key_path, box_path = self._record_paths(sid, rid)
        try:
            with open(key_path, "rb") as f:
                record_key = SecretBox(self._master).decrypt(f.read())
            with open(box_path, "rb") as f:
                return SecretBox(record_key).decrypt(f.read())
        except (FileNotFoundError, CryptoError) as e:
            raise KeyError(f"record {sid}/{rid} is gone or unreadable") from e

    def list_subjects(self) -> list[str]:
        if not os.path.isdir(self.subjects):
            return []
        return sorted(os.listdir(self.subjects))

    def subject_records(self, sid: str) -> list[str]:
        d = self._subject_dir(sid)
        if not os.path.isdir(d):
            return []
        return sorted(f[:-4] for f in os.listdir(d) if f.endswith(".box"))

    # -- erasure ----------------------------------------------------------
    def shred_record(self, sid: str, rid: str) -> dict:
        key_path, box_path = self._record_paths(sid, rid)
        shredded = 0
        missing = []
        for p in (key_path, box_path):
            if os.path.exists(p):
                shredded += shred_file(p)
            else:
                missing.append(os.path.basename(p))
        if not missing and not os.path.exists(os.path.join(self._subject_dir(sid), "meta.json")):
            missing.append("meta.json")

        # prune metadata: drop the record entry, and the subject dir if empty
        meta_path = os.path.join(self._subject_dir(sid), "meta.json")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
            meta["records"] = [r for r in meta.get("records", []) if r.get("rid") != rid]
            if meta["records"]:
                with open(meta_path, "w") as f:
                    json.dump(meta, f, indent=1)
            else:
                shred_file(meta_path)

        d = self._subject_dir(sid)
        if os.path.isdir(d) and not os.listdir(d):
            os.rmdir(d)
            _fsync_dir(self.subjects)
        return {"sid": sid, "rid": rid, "bytes_shredded": shredded, "already_missing": missing}

    def shred_subject(self, sid: str) -> dict:
        records = self.subject_records(sid)
        total = 0
        for rid in records:
            total += self.shred_record(sid, rid)["bytes_shredded"]
        d = self._subject_dir(sid)
        if os.path.isdir(d):
            # anything left over (stray files) gets the same treatment
            for name in os.listdir(d):
                total += shred_file(os.path.join(d, name))
            os.rmdir(d)
            _fsync_dir(self.subjects)
        return {"sid": sid, "records_shredded": len(records), "bytes_shredded": total}
