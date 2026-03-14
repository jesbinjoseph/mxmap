import csv
import io
import time

import httpx

from mail_sovereignty.constants import BFS_API_URL, CANTON_SHORT_TO_FULL


def _parse_csv_response(text: str) -> list[dict]:
    """Parse the BFS API CSV response into a list of dicts."""
    reader = csv.DictReader(io.StringIO(text))
    entries = []
    for row in reader:
        entries.append(
            {
                "historicalCode": int(row["HistoricalCode"]),
                "bfsCode": int(row["BfsCode"]),
                "level": int(row["Level"]),
                "parent": int(row["Parent"]) if row.get("Parent") else None,
                "name": row["Name"],
                "shortName": row["ShortName"],
            }
        )
    return entries


async def fetch_bfs_municipalities(date: str | None = None) -> dict[str, dict]:
    """Fetch municipality list from BFS REST API.

    Args:
        date: Optional date in DD-MM-YYYY format. Defaults to today.

    Returns:
        Dict mapping BFS code (str) to {"bfs", "name", "canton"}.
    """
    if date is None:
        date = time.strftime("%d-%m-%Y")

    print(f"Fetching BFS municipality list (date={date})...")

    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(BFS_API_URL, params={"date": date})
        r.raise_for_status()
        entries = _parse_csv_response(r.text)

    # Build lookup by HistoricalCode for parent resolution
    by_hist_code: dict[int, dict] = {}
    for entry in entries:
        by_hist_code[entry["historicalCode"]] = entry

    # Filter to Level 3 (communes) and resolve cantons
    municipalities: dict[str, dict] = {}
    for entry in entries:
        if entry["level"] != 3:
            continue

        bfs_code = str(entry["bfsCode"])
        name = entry["name"]

        # Resolve canton: commune -> district (Level 2) -> canton (Level 1)
        canton = ""
        parent = by_hist_code.get(entry.get("parent"))
        if parent and parent["level"] == 2:
            grandparent = by_hist_code.get(parent.get("parent"))
            if grandparent and grandparent["level"] == 1:
                canton_short = grandparent.get("shortName", "").lower()
                canton = CANTON_SHORT_TO_FULL.get(canton_short, "")
        elif parent and parent["level"] == 1:
            # Direct parent is canton (some cantons have no districts)
            canton_short = parent.get("shortName", "").lower()
            canton = CANTON_SHORT_TO_FULL.get(canton_short, "")

        municipalities[bfs_code] = {
            "bfs": bfs_code,
            "name": name,
            "canton": canton,
        }

    print(f"  Found {len(municipalities)} municipalities from BFS API")
    return municipalities
