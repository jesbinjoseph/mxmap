import argparse
import asyncio
from pathlib import Path


def resolve_domains() -> None:
    from mail_sovereignty.resolve import run

    parser = argparse.ArgumentParser(description="Resolve municipality email domains")
    parser.add_argument("--date", help="BFS snapshot date (DD-MM-YYYY)", default=None)
    args = parser.parse_args()

    asyncio.run(
        run(Path("municipality_domains.json"), Path("overrides.json"), date=args.date)
    )


def classify_providers() -> None:
    from mail_sovereignty.classify_pipeline import run

    asyncio.run(run(Path("municipality_domains.json"), Path("data.json")))


def validate() -> None:
    from mail_sovereignty.validate import run

    run(Path("data.json"), Path("."), quality_gate=True)
