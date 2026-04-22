"""Posture signals (DMARC, DNSSEC, hosting) for the mail-sovereignty pipeline.

Posture signals describe how well a domain is configured. They are kept
separate from ``classifier.py`` so they do not shift the provider vote — the
``WEIGHTS`` invariant (sum to 1.0) enforced by ``tests/test_probes.py`` must
remain undisturbed.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from .dns import resolve_robust
from .geoip import lookup_asn
from .signatures import FOREIGN_CLOUD_ASNS, INDIAN_GOV_ASNS, INDIAN_ISP_ASNS

DmarcTier = Literal["green", "amber", "red", "missing"]
DmarcPolicy = Literal["none", "quarantine", "reject"]
HostingTier = Literal[
    "india-govt", "india-private", "foreign-cloud", "foreign-other", "unknown"
]


class DmarcPosture(BaseModel):
    model_config = ConfigDict(frozen=True)

    present: bool
    policy: DmarcPolicy | None = None
    subdomain_policy: DmarcPolicy | None = None
    pct: int | None = None
    rua: list[str] = []
    ruf: list[str] = []
    tier: DmarcTier
    raw: str = ""


def _parse_dmarc_record(txt: str) -> dict[str, str]:
    """Parse a DMARC TXT record into a tag→value dict. First-occurrence wins."""
    tags: dict[str, str] = {}
    for part in txt.split(";"):
        token = part.strip()
        if not token or "=" not in token:
            continue
        key, _, value = token.partition("=")
        key = key.strip().lower()
        if key and key not in tags:
            tags[key] = value.strip()
    return tags


def _classify_dmarc(
    present: bool,
    policy: DmarcPolicy | None,
    pct: int | None,
) -> DmarcTier:
    if not present:
        return "missing"
    if policy is None:
        return "red"  # record present but malformed (no p=)
    if policy == "reject":
        return "green" if pct is None or pct >= 100 else "amber"
    if policy == "quarantine":
        return "amber"
    return "red"  # p=none


async def probe_dmarc_posture(domain: str) -> DmarcPosture:
    """Fetch and classify the DMARC policy for a domain.

    Returns a posture model describing whether DMARC is present, its policy,
    reporting URIs, and a green/amber/red/missing tier suitable for the
    frontend legend.
    """
    answer = await resolve_robust(f"_dmarc.{domain}", "TXT")
    if answer is None:
        return DmarcPosture(present=False, tier="missing")

    raw = ""
    for rdata in answer:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if txt.lower().lstrip().startswith("v=dmarc1"):
            raw = txt
            break

    if not raw:
        return DmarcPosture(present=False, tier="missing")

    tags = _parse_dmarc_record(raw)

    def _policy(val: str | None) -> DmarcPolicy | None:
        if val in ("none", "quarantine", "reject"):
            return val  # type: ignore[return-value]
        return None

    def _uris(val: str | None) -> list[str]:
        if not val:
            return []
        return [u.strip() for u in val.split(",") if u.strip()]

    policy = _policy(tags.get("p"))
    subdomain_policy = _policy(tags.get("sp")) or policy

    pct: int | None = None
    pct_raw = tags.get("pct")
    if pct_raw and pct_raw.isdigit():
        pct = int(pct_raw)

    tier = _classify_dmarc(present=True, policy=policy, pct=pct)

    return DmarcPosture(
        present=True,
        policy=policy,
        subdomain_policy=subdomain_policy,
        pct=pct,
        rua=_uris(tags.get("rua")),
        ruf=_uris(tags.get("ruf")),
        tier=tier,
        raw=raw,
    )


class HostingAsn(BaseModel):
    model_config = ConfigDict(frozen=True)

    asn: int
    name: str  # friendly provider name when known, else ""
    country: str  # ISO 3166-1 alpha-2, "" if unknown
    mx_host: str  # the MX hostname this ASN was resolved from


class HostingPosture(BaseModel):
    model_config = ConfigDict(frozen=True)

    tier: HostingTier
    asns: list[HostingAsn] = []
    # Every unique country observed across the MX IP fleet, e.g. ["IN", "US"].
    countries: list[str] = []


def _classify_hosting_asn(asn: int) -> HostingTier:
    if asn in INDIAN_GOV_ASNS:
        return "india-govt"
    if asn in FOREIGN_CLOUD_ASNS:
        return "foreign-cloud"
    if asn in INDIAN_ISP_ASNS:
        return "india-private"
    return "foreign-other"


# Ordered by sovereignty priority — if any MX lands in india-govt, the
# domain is classified as sovereign regardless of whether other MXs are
# foreign. Conversely, foreign-cloud wins over foreign-other.
_TIER_PRIORITY: list[HostingTier] = [
    "india-govt",
    "india-private",
    "foreign-cloud",
    "foreign-other",
]


def _aggregate_tier(tiers: list[HostingTier]) -> HostingTier:
    if not tiers:
        return "unknown"
    for t in _TIER_PRIORITY:
        if t in tiers:
            return t
    return "unknown"


async def probe_hosting(mx_hosts: list[str]) -> HostingPosture:
    """Resolve MX IPs → ASN/country via Team Cymru, classify sovereignty.

    Sovereignty tier is the highest-priority tier observed across all MX hosts:
    india-govt > india-private > foreign-cloud > foreign-other. Multiple MXs
    hitting different tiers produces the most-sovereign hit (a single
    NIC-hosted backup still counts as a sovereign deployment).
    """
    if not mx_hosts:
        return HostingPosture(tier="unknown")

    seen_asns: dict[int, HostingAsn] = {}
    countries: set[str] = set()
    tiers: list[HostingTier] = []

    for host in mx_hosts:
        a_answer = await resolve_robust(host, "A")
        if a_answer is None:
            continue
        for rdata in a_answer:
            ip = str(rdata)
            info = await lookup_asn(ip)
            if info is None:
                continue
            if info.country:
                countries.add(info.country)
            if info.asn in seen_asns:
                continue
            name = (
                INDIAN_GOV_ASNS.get(info.asn)
                or FOREIGN_CLOUD_ASNS.get(info.asn)
                or INDIAN_ISP_ASNS.get(info.asn)
                or ""
            )
            seen_asns[info.asn] = HostingAsn(
                asn=info.asn,
                name=name,
                country=info.country,
                mx_host=host,
            )
            tiers.append(_classify_hosting_asn(info.asn))

    return HostingPosture(
        tier=_aggregate_tier(tiers),
        asns=list(seen_asns.values()),
        countries=sorted(countries),
    )
