import argparse
import asyncio
from pathlib import Path

from mail_sovereignty.log import setup as setup_logging


def resolve_domains() -> None:
    from mail_sovereignty.resolve import run

    parser = argparse.ArgumentParser(description="Resolve municipality email domains")
    parser.add_argument("--date", help="BFS snapshot date (DD-MM-YYYY)", default=None)
    parser.set_defaults(include_igod_districts=True)
    parser.add_argument(
        "--include-igod-districts",
        dest="include_igod_districts",
        action="store_true",
        help="Include districts scraped from https://igod.gov.in/sg/states (default)",
    )
    parser.add_argument(
        "--no-include-igod-districts",
        dest="include_igod_districts",
        action="store_false",
        help="Disable iGOD district enrichment",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    asyncio.run(
        run(
            Path("municipality_domains.json"),
            Path("overrides.json"),
            date=args.date,
            include_igod_districts=args.include_igod_districts,
        )
    )


def classify_providers() -> None:
    from mail_sovereignty.pipeline import run

    parser = argparse.ArgumentParser(
        description="Classify municipality email providers"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    asyncio.run(run(Path("municipality_domains.json"), Path("data.json")))


def analyze() -> None:
    from mail_sovereignty.analyze import main

    main()
