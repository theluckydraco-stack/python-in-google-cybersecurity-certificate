from __future__ import annotations

import argparse
from pathlib import Path

from .core import approve_demo_mappings, candidate_mappings, load_observations, write_outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Map CTI observations to ATT&CK and draft detections")
    parser.add_argument("input", type=Path, help="JSON array of normalized CTI observations")
    parser.add_argument("--out", type=Path, default=Path("build"), help="output directory")
    parser.add_argument(
        "--auto-approve-demo",
        action="store_true",
        help="approve synthetic demo mappings; never use as a production review shortcut",
    )
    args = parser.parse_args()

    observations = load_observations(args.input)
    mappings = candidate_mappings(observations)
    if args.auto_approve_demo:
        approve_demo_mappings(mappings)
    write_outputs(mappings, args.out)

    approved = sum(item["review"]["status"] == "approved" for item in mappings)
    print(f"observations={len(observations)} candidates={len(mappings)} approved={approved}")
    print(f"outputs={args.out}")


if __name__ == "__main__":
    main()
