"""ASN + country lookup for IPs via Team Cymru's DNS service.

The Cymru ``origin.asn.cymru.com`` TXT record format is::

    "ASN | PREFIX | COUNTRY | REGISTRY | ALLOC_DATE"

We use this instead of MaxMind/GeoLite2 because it requires no database file,
no license key, and is already the resolver ``probes.probe_asn`` relies on.
"""

from __future__ import annotations

from typing import NamedTuple

from .dns import resolve_robust


class AsnInfo(NamedTuple):
    asn: int
    country: str  # ISO 3166-1 alpha-2, "" if unknown
    prefix: str  # announced prefix, "" if unknown


async def lookup_asn(ip: str) -> AsnInfo | None:
    """Look up the origin ASN and country for an IPv4 address.

    Returns None if the Cymru service returns no answer or the record is
    malformed.
    """
    if not ip or ":" in ip:  # skip IPv6 for now — needs origin6 zone
        return None
    reversed_ip = ".".join(reversed(ip.split(".")))
    answer = await resolve_robust(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
    if answer is None:
        return None
    for rdata in answer:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        parts = [p.strip() for p in txt.split("|")]
        if len(parts) < 3:
            continue
        try:
            asn = int(parts[0].split()[0])
        except (ValueError, IndexError):
            continue
        prefix = parts[1]
        country = parts[2].upper() if parts[2] else ""
        return AsnInfo(asn=asn, country=country, prefix=prefix)
    return None
