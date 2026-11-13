"""the recovery attacker: hunts raw bytes for the subject's markers.

this is the instrument that makes erasure *provable*. sql `delete`
removes rows from a query's view of the world; it does not remove bytes
from the disk. the freelist pages, the wal, the journal, the slack in
untouched pages - the data is all still there, and a forensic attacker
gets it for free. this module scans the raw files the way such an
attacker would: no schema, no queries, just byte pattern search over
the database file and every sidecar sqlite drags behind it.

the drill uses it twice: once after a naive delete (it must recover the
subject - proving the gap), once after the shredder (it must recover
nothing - proving the fix). same tool, same markers, different world.
"""

import glob
import os

SIDECARS = ("-wal", "-shm", "-journal")


def sidecar_paths(path: str) -> list[str]:
    return [p for p in (path + s for s in SIDECARS) if os.path.exists(p)]


def scan_targets(path: str) -> list[str]:
    """the db file plus every sidecar that exists right now."""
    return [path] + sidecar_paths(path)


def scan(path: str, markers: list[str]) -> dict:
    """count recoverable fragments of each marker across raw files.

    a fragment is one occurrence of the marker's bytes. this is simple
    substring carving on purpose: if even the dumbest attacker can
    recover the data, 'erased' is a lie. subtle steganographic recovery
    is the shredder's problem to prevent, not the attacker's to discover.
    """
    targets = scan_targets(path)
    results = {}
    files_scanned = []
    for marker in markers:
        needle = marker.encode()
        hits = []
        for t in targets:
            size = os.path.getsize(t)
            if size == 0:
                continue
            with open(t, "rb") as f:
                blob = f.read()
            count = blob.count(needle)
            if count:
                hits.append({"file": os.path.basename(t), "fragments": count,
                             "bytes": count * len(needle)})
            files_scanned.append(t)
        results[marker] = {
            "fragments": sum(h["fragments"] for h in hits),
            "bytes_recoverable": sum(h["bytes"] for h in hits),
            "locations": hits,
        }
    return {
        "targets": sorted(set(files_scanned)),
        "markers": results,
        "total_fragments": sum(r["fragments"] for r in results.values()),
        "total_bytes_recoverable": sum(r["bytes_recoverable"] for r in results.values()),
    }


def scan_tree(root: str, markers: list[str]) -> dict:
    """same hunt across a directory tree (envelope stores, exports)."""
    results = {}
    files_scanned = 0
    for marker in markers:
        needle = marker.encode()
        fragments = 0
        bytes_rec = 0
        locations = []
        for dirpath, _dirs, names in os.walk(root):
            for name in names:
                p = os.path.join(dirpath, name)
                if not os.path.isfile(p) or os.path.getsize(p) == 0:
                    continue
                files_scanned += 1
                with open(p, "rb") as f:
                    blob = f.read()
                count = blob.count(needle)
                if count:
                    fragments += count
                    bytes_rec += count * len(needle)
                    locations.append({"file": os.path.relpath(p, root),
                                      "fragments": count})
        results[marker] = {"fragments": fragments, "bytes_recoverable": bytes_rec,
                           "locations": locations}
    return {
        "files_scanned": files_scanned,
        "markers": results,
        "total_fragments": sum(r["fragments"] for r in results.values()),
        "total_bytes_recoverable": sum(r["bytes_recoverable"] for r in results.values()),
    }


def stray_files(pattern: str) -> list[str]:
    """sidecars left lying around under a glob (drift detection)."""
    return sorted(glob.glob(pattern))
