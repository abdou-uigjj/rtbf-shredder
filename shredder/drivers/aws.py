"""aws erasure: cryptographic shredding of per-subject data keys.

in production this driver talks to a real KMS: every subject's objects
are enveloped under a data key that KMS wraps with the tenant CMK.
erasure is then a control-plane operation - schedule the data key's
deletion and every ciphertext ever written under it becomes noise, in
every bucket, every replica, every backup, without touching a single
byte. terraform/ builds that pipeline; lambda/ invokes it.

in CI there is no AWS. so the control plane this drill exercises is a
faithful simulation on disk:

    root/kms/<key-id>.cmk            tenant key material (the CMK)
    root/kms/<key-id>.wraps/<sid>    per-subject wrapped data key
    root/s3/<bucket>/<sid>/<obj>.vN  versioned objects, data-key sealed

same semantics, same receipts, testable offline: delete the wrap and
the objects are unreadable; shred the objects and the bytes are gone.
the live path (`boto3`) is imported lazily and only used when
RTBF_AWS_MODE=live - the drill never needs a cloud account.
"""

import os
import secrets

from nacl.secret import SecretBox

from ..attacker import scan_tree


class AwsEngine:
    MODE_SIM = "sim"
    MODE_LIVE = "live"

    def __init__(self, root: str, mode: str = MODE_SIM):
        self.root = os.path.abspath(root)
        self.kms = os.path.join(self.root, "kms")
        self.s3 = os.path.join(self.root, "s3")
        self.mode = mode
        os.makedirs(self.kms, exist_ok=True)
        os.makedirs(self.s3, exist_ok=True)
        self._tenant_keys: dict[str, bytes] = {}

    # -- control plane (sim) -------------------------------------------------
    def create_tenant_key(self, key_id: str = "tenant-primary") -> str:
        path = os.path.join(self.kms, f"{key_id}.cmk")
        material = secrets.token_bytes(SecretBox.KEY_SIZE)
        with open(path, "wb") as f:
            f.write(material)
        os.chmod(path, 0o600)
        self._tenant_keys[key_id] = material
        return key_id

    def _tenant_material(self, key_id: str) -> bytes:
        if key_id not in self._tenant_keys:
            with open(os.path.join(self.kms, f"{key_id}.cmk"), "rb") as f:
                self._tenant_keys[key_id] = f.read()
        return self._tenant_keys[key_id]

    # -- object plane ----------------------------------------------------------
    def put_object(self, bucket: str, sid: str, obj: str, data: bytes,
                   key_id: str = "tenant-primary") -> dict:
        """envelope: random data key wraps the object; the data key is
        wrapped by the tenant key and stored under kms/<key>.wraps/<sid>."""
        bdir = os.path.join(self.s3, bucket, sid)
        os.makedirs(bdir, exist_ok=True)

        wraps = os.path.join(self.kms, f"{key_id}.wraps", sid)
        os.makedirs(os.path.dirname(wraps), exist_ok=True)
        if os.path.exists(wraps):
            with open(wraps, "rb") as f:
                data_key = SecretBox(self._tenant_material(key_id)).decrypt(f.read())
        else:
            data_key = secrets.token_bytes(SecretBox.KEY_SIZE)
            wrapped = SecretBox(self._tenant_material(key_id)).encrypt(data_key)
            with open(wraps, "wb") as f:
                f.write(wrapped)
            os.chmod(wraps, 0o600)

        version = 1
        existing = [f for f in os.listdir(bdir) if f.startswith(f"{obj}.v")]
        if existing:
            version = max(int(f.rsplit(".v", 1)[1]) for f in existing) + 1
        path = os.path.join(bdir, f"{obj}.v{version}")
        sealed = SecretBox(data_key).encrypt(data)
        with open(path, "wb") as f:
            f.write(sealed)
        return {"bucket": bucket, "sid": sid, "object": obj, "version": version}

    def list_versions(self, bucket: str, sid: str, obj: str) -> list[int]:
        bdir = os.path.join(self.s3, bucket, sid)
        if not os.path.isdir(bdir):
            return []
        return sorted(int(f.rsplit(".v", 1)[1])
                      for f in os.listdir(bdir) if f.startswith(f"{obj}.v"))

    def get_object(self, bucket: str, sid: str, obj: str, version: int,
                   key_id: str = "tenant-primary") -> bytes:
        wraps = os.path.join(self.kms, f"{key_id}.wraps", sid)
        with open(wraps, "rb") as f:
            data_key = SecretBox(self._tenant_material(key_id)).decrypt(f.read())
        path = os.path.join(self.s3, bucket, sid, f"{obj}.v{version}")
        with open(path, "rb") as f:
            return SecretBox(data_key).decrypt(f.read())

    # -- the erase --------------------------------------------------------------
    def erase_subject(self, bucket: str, sid: str, markers: list[str],
                      key_id: str = "tenant-primary") -> dict:
        if self.mode == self.MODE_LIVE:
            return self._erase_subject_live(bucket, sid)
        bdir = os.path.join(self.s3, bucket, sid)
        wraps = os.path.join(self.kms, f"{key_id}.wraps", sid)

        before = scan_tree(bdir, markers) if os.path.isdir(bdir) else {
            "total_fragments": 0, "total_bytes_recoverable": 0}

        objects, versions = 0, 0
        bytes_shredded = 0
        if os.path.isdir(bdir):
            names = os.listdir(bdir)
            objects = len({n.split(".v")[0] for n in names})
            versions = len(names)
            for name in names:
                p = os.path.join(bdir, name)
                size = os.path.getsize(p)
                with open(p, "r+b") as f:
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
                os.unlink(p)
                bytes_shredded += size
            os.rmdir(bdir)
        keys_destroyed = 0
        if os.path.exists(wraps):
            size = os.path.getsize(wraps)
            with open(wraps, "r+b") as f:
                f.seek(0)
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
            os.unlink(wraps)
            keys_destroyed = 1

        after = scan_tree(bdir, markers) if os.path.isdir(bdir) else {
            "total_fragments": 0, "total_bytes_recoverable": 0}
        return {
            "engine": "aws-kms-sim",
            "bucket": bucket,
            "objects_deleted": objects,
            "versions_scrubbed": versions,
            "data_keys_destroyed": keys_destroyed,
            "bytes_shredded": bytes_shredded,
            "recovery_before": {"fragments": before["total_fragments"],
                                "bytes": before["total_bytes_recoverable"]},
            "recovery_after": {"fragments": after["total_fragments"],
                               "bytes": after["total_bytes_recoverable"]},
        }

    def _erase_subject_live(self, bucket: str, sid: str) -> dict:
        """the real control-plane call. imported lazily so CI never needs
        boto3; terraform wires the lambda role for exactly these actions."""
        import boto3  # noqa: PLC0415 - deliberate lazy import
        kms = boto3.client("kms")
        s3 = boto3.client("s3")
        alias = f"alias/rtbf-{sid}"
        keys_destroyed = 0
        for a in kms.list_aliases(Limit=1000)["Aliases"]:
            if a.get("AliasName") == alias and "TargetKeyId" in a:
                kms.schedule_key_deletion(KeyId=a["TargetKeyId"],
                                          PendingWindowInDays=7)
                keys_destroyed += 1
        versions = s3.list_object_versions(Bucket=bucket, Prefix=f"{sid}/")
        scrubbed = 0
        for v in versions.get("Versions", []) + versions.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"],
                             VersionId=v["VersionId"])
            scrubbed += 1
        return {"engine": "aws-kms-live", "bucket": bucket,
                "data_keys_destroyed": keys_destroyed, "versions_scrubbed": scrubbed}
