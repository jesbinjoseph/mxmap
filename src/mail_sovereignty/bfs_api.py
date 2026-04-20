import csv
import io
import time
from pathlib import Path

import httpx
import stamina
from loguru import logger


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=3,
    wait_initial=2.0,
)
async def _fetch(client: httpx.AsyncClient, url: str, params: dict) -> httpx.Response:
    r = await client.get(url, params=params)
    r.raise_for_status()
    return r


def _parse_csv_response(text: str) -> list[dict]:
    """Parse a municipality CSV into a list of dicts.

    Expected columns: LGDCode,Name,State,Type
    Type: MC (Municipal Corporation), M (Municipality), NP (Nagar Panchayat),
          CT (Census Town), Cap (State Capital)
    """
    reader = csv.DictReader(io.StringIO(text))
    entries = []
    for row in reader:
        entries.append(
            {
                "lgdCode": row["LGDCode"].strip(),
                "name": row["Name"].strip(),
                "state": row["State"].strip(),
                "type": row.get("Type", "M").strip(),
            }
        )
    return entries


async def fetch_bfs_municipalities(date: str | None = None) -> dict[str, dict]:
    """Fetch Indian municipality list from local CSV data.

    The Indian Local Government Directory doesn't provide a convenient
    REST API like Switzerland's BFS. We use a curated CSV of major
    Indian municipalities (municipal corporations, municipalities,
    nagar panchayats) with their LGD codes.

    Args:
        date: Ignored (kept for interface compatibility).

    Returns:
        Dict mapping LGD code (str) to {"bfs": lgd_code, "name", "canton": state}.
    """
    csv_path = Path(__file__).parent.parent.parent / "indian_municipalities.csv"
    if not csv_path.exists():
        logger.warning(
            "indian_municipalities.csv not found at {}, returning empty list",
            csv_path,
        )
        return {}

    logger.info("Loading Indian municipalities from {}...", csv_path)
    t0 = time.monotonic()

    text = csv_path.read_text(encoding="utf-8")
    entries = _parse_csv_response(text)

    municipalities: dict[str, dict] = {}
    for entry in entries:
        lgd_code = entry["lgdCode"]
        name = entry["name"]
        state = entry["state"]
        entity_type = entry.get("type", "M")

        municipalities[lgd_code] = {
            "bfs": lgd_code,
            "name": name,
            "canton": state,
            "type": entity_type,
        }

    logger.info(
        "Loaded {} municipalities in {:.1f}s",
        len(municipalities),
        time.monotonic() - t0,
    )
    return municipalities
