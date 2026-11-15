"""walk a ledger export and prove the chain holds end to end."""

import argparse
import sys

sys.path.insert(0, ".")

from shredder.ledger import Ledger  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="verify the erasure ledger chain")
    ap.add_argument("ledger", help="ledger.jsonl export")
    args = ap.parse_args()
    led = Ledger(args.ledger)
    v = led.verify()
    print(f"entries     : {v['entries']}")
    print(f"head        : {v.get('head', '-')[:16]}..." if v.get("head") else "head: -")
    print(f"chain       : {'INTACT' if v['ok'] else 'BROKEN'}"
          + ("" if v["ok"] else f" ({v['reason']})"))
    if v["ok"]:
        actions = {}
        for e in led.entries():
            actions[e["action"]] = actions.get(e["action"], 0) + 1
        for a, n in sorted(actions.items()):
            print(f"  {a:<32} x{n}")
    return 0 if v["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
