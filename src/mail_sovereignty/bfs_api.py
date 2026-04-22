import asyncio
import csv
import hashlib
import html
import io
import re
import time
from pathlib import Path

import httpx
import stamina
from loguru import logger

IGOD_STATES_URL = "https://igod.gov.in/sg/states"
IGOD_DISTRICT_STATES_URL = "https://igod.gov.in/sg/district/states"
IGOD_DISTRICT_TYPE = "District"
IGOD_ID_MIN = 900000000
IGOD_ID_MAX = 999999999

_WS_RE = re.compile(r"\s+")
_DISTRICT_SUFFIX_RE = re.compile(r"\s+district$", re.IGNORECASE)


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


def _clean_html_text(raw: str) -> str:
    text = re.sub(r"<[^>]+>", " ", raw)
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def _normalize_state_name(name: str) -> str:
    return _WS_RE.sub(" ", name).strip().casefold()


def _normalize_entity_name(name: str) -> str:
    normalized = _WS_RE.sub(" ", name).strip()
    normalized = _DISTRICT_SUFFIX_RE.sub("", normalized)
    return normalized.casefold()


def _extract_igod_state_links(page_html: str) -> list[tuple[str, str]]:
    """Extract (state_name, district_page_url) pairs from iGOD state pages."""
    patterns = [
        re.compile(
            r'<a[^>]+href="https?://igod\.gov\.in/sg/([A-Z]{2})/categories"[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            r'<a[^>]+href="https?://igod\.gov\.in/sg/([A-Z]{2})/E042/organizations"[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        ),
    ]

    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for pattern in patterns:
        for state_code, state_raw in pattern.findall(page_html):
            state_name = _clean_html_text(state_raw)
            if not state_name:
                continue
            district_url = (
                f"https://igod.gov.in/sg/{state_code.upper()}/E042/organizations"
            )
            dedupe_key = f"{state_name}|{district_url}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            results.append((state_name, district_url))
    return results


def _extract_igod_district_names(page_html: str) -> list[str]:
    """Extract district names from an iGOD district listing page."""
    start = page_html.find('<div class="search-content">')
    content = page_html[start:] if start >= 0 else page_html

    for marker in (
        '<section class="in-focus-new-addition-outer"',
        '<div class="in-focus-new-addition-outer"',
    ):
        idx = content.find(marker)
        if idx >= 0:
            content = content[:idx]
            break

    names: list[str] = []
    patterns = [
        re.compile(
            r'<a[^>]*class="[^"]*search-title[^"]*"[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            r'<div[^>]*class="[^"]*search-title[^"]*"[^>]*>(.*?)</div>',
            re.IGNORECASE | re.DOTALL,
        ),
    ]
    for pattern in patterns:
        for raw in pattern.findall(content):
            name = _clean_html_text(raw)
            if not name:
                continue
            names.append(name)

    # Preserve order, remove duplicates.
    deduped: list[str] = []
    seen: set[str] = set()
    for name in names:
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(name)
    return deduped


async def fetch_igod_districts() -> list[dict[str, str]]:
    """Scrape district names from iGOD state pages."""
    logger.info("Fetching district lists from iGOD state pages...")
    t0 = time.monotonic()

    async with httpx.AsyncClient(
        timeout=30,
        follow_redirects=True,
        headers={"User-Agent": "MXmap/1.0 (https://github.com/davidhuser/mxmap)"},
    ) as client:
        states_response = await _fetch(client, IGOD_STATES_URL, {})
        states = _extract_igod_state_links(states_response.text)

        if not states:
            logger.warning(
                "No state links found at {}, trying fallback {}",
                IGOD_STATES_URL,
                IGOD_DISTRICT_STATES_URL,
            )
            fallback_response = await _fetch(client, IGOD_DISTRICT_STATES_URL, {})
            states = _extract_igod_state_links(fallback_response.text)

        if not states:
            logger.warning("Could not extract state links from iGOD pages")
            return []

        semaphore = asyncio.Semaphore(8)

        async def _fetch_state_districts(
            state_name: str, district_url: str
        ) -> list[dict[str, str]]:
            async with semaphore:
                try:
                    response = await _fetch(client, district_url, {})
                except Exception as exc:
                    logger.warning(
                        "Failed to fetch iGOD districts for {} ({}): {}",
                        state_name,
                        district_url,
                        exc,
                    )
                    return []
                names = _extract_igod_district_names(response.text)
                return [
                    {
                        "name": district_name,
                        "state": state_name,
                        "type": IGOD_DISTRICT_TYPE,
                    }
                    for district_name in names
                ]

        chunks = await asyncio.gather(
            *[_fetch_state_districts(state, url) for state, url in states]
        )

    districts = [entry for chunk in chunks for entry in chunk]
    logger.info(
        "Fetched {} iGOD district entries across {} states in {:.1f}s",
        len(districts),
        len(states),
        time.monotonic() - t0,
    )
    return districts


def _generate_igod_code(state: str, name: str, used_codes: set[str]) -> str:
    seed = f"igod|{state.strip().casefold()}|{name.strip().casefold()}"
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    candidate = IGOD_ID_MIN + (int(digest[:8], 16) % (IGOD_ID_MAX - IGOD_ID_MIN + 1))
    while str(candidate) in used_codes:
        candidate += 1
        if candidate > IGOD_ID_MAX:
            candidate = IGOD_ID_MIN
    code = str(candidate)
    used_codes.add(code)
    return code


async def fetch_bfs_municipalities(
    date: str | None = None,
    include_igod_districts: bool = False,
) -> dict[str, dict]:
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

    if include_igod_districts:
        try:
            igod_entries = await fetch_igod_districts()
        except Exception as exc:
            logger.warning(
                "Failed to load iGOD districts, continuing with CSV only: {}", exc
            )
            igod_entries = []

        if igod_entries:
            existing_codes = set(municipalities.keys())
            existing_entities = {
                (
                    _normalize_entity_name(item["name"]),
                    _normalize_state_name(item["canton"]),
                    item.get("type", "").casefold(),
                )
                for item in municipalities.values()
            }

            added = 0
            for entry in igod_entries:
                key = (
                    _normalize_entity_name(entry["name"]),
                    _normalize_state_name(entry["state"]),
                    IGOD_DISTRICT_TYPE.casefold(),
                )
                if key in existing_entities:
                    continue

                lgd_code = _generate_igod_code(
                    state=entry["state"],
                    name=entry["name"],
                    used_codes=existing_codes,
                )
                municipalities[lgd_code] = {
                    "bfs": lgd_code,
                    "name": entry["name"],
                    "canton": entry["state"],
                    "type": IGOD_DISTRICT_TYPE,
                }
                existing_entities.add(key)
                added += 1

            logger.info("Added {} iGOD districts to municipality list", added)

    logger.info(
        "Loaded {} municipalities in {:.1f}s",
        len(municipalities),
        time.monotonic() - t0,
    )
    return municipalities
