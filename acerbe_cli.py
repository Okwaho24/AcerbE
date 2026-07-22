#!/usr/bin/env python3
"""
AcerbE™ v3.1.0 — CLI
Archer Chain Analytics™ | Mahihkan.com

Usage:
  python acerbe_cli.py embed <file> [--owner ID] [--output DIR] [--notes TEXT]
  python acerbe_cli.py verify <file>
"""

import argparse, sys, os, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from acerbe.engine import embed_fingerprint, verify_fingerprint

BAR = "─" * 52


def get_key() -> str:
    key = os.environ.get("ACERBE_SECRET_KEY", "")
    if not key:
        print("[FATAL] ACERBE_SECRET_KEY not set. Aborting.")
        sys.exit(1)
    return key


def cmd_embed(args):
    key  = get_key()
    path = Path(args.file)
    if not path.exists():
        print(f"[ERROR] Not found: {path}")
        sys.exit(1)

    out_dir = Path(args.output) if args.output else path.parent / "acerbe_output"
    print(f"\nAcerbE™ v3.1.0  |  Archer Chain Analytics™")
    print(BAR)
    print(f"File   : {path.name}  ({path.stat().st_size:,} bytes)")
    print(f"Owner  : {args.owner}")

    out_path, manifest_path, manifest = embed_fingerprint(
        file_path=path,
        owner_id=args.owner,
        secret_key=key,
        output_dir=out_dir,
        notes=args.notes or None,
    )

    print(manifest.summary())
    print(f"Output   : {out_path}")
    print(f"Manifest : {manifest_path}")
    print(BAR + "\n")


def cmd_verify(args):
    key  = get_key()
    path = Path(args.file)
    if not path.exists():
        print(f"[ERROR] Not found: {path}")
        sys.exit(1)

    print(f"\nAcerbE™ v3.1.0  |  Verification")
    print(BAR)
    report = verify_fingerprint(path, key)
    print(json.dumps(report, indent=2))
    print(BAR)
    print("RESULT:", "VERIFIED ✓" if report.get("verified") else "NOT VERIFIED ✗")
    print()


def main():
    p = argparse.ArgumentParser(
        description="AcerbE™ v3.1.0 | Archer Chain Analytics™"
    )
    sub = p.add_subparsers(dest="cmd")

    ep = sub.add_parser("embed")
    ep.add_argument("file")
    ep.add_argument("--owner",  default="Mahihkan")
    ep.add_argument("--output", default=None)
    ep.add_argument("--notes",  default="")

    vp = sub.add_parser("verify")
    vp.add_argument("file")

    args = p.parse_args()
    if args.cmd == "embed":
        cmd_embed(args)
    elif args.cmd == "verify":
        cmd_verify(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
