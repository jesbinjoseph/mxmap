import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx

from mail_sovereignty.classify import (
    classify_from_smtp_banner,
    classify_with_evidence,
)
from mail_sovereignty.constants import (
    CONCURRENCY,
    CONCURRENCY_SMTP,
    CONCURRENCY_TENANT,
)
from mail_sovereignty.evidence import (
    SIGNAL_GROUP_WEIGHTS,
    SIGNAL_TO_GROUP,
    Signal,
    resolve_provider,
)
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_dkim_selectors,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)
from mail_sovereignty.smtp import fetch_smtp_banner
from mail_sovereignty.tenant import check_microsoft_tenant


def recalculate_confidence(entry: dict[str, Any]) -> None:
    """Reconstruct Signals from classification_signals and update confidence."""
    raw_signals = entry.get("classification_signals")
    if not raw_signals:
        return
    signals = [
        Signal(
            source=s["source"],
            provider=s.get("provider"),
            weight=s.get("weight", 0.0),
            detail=s.get("detail", ""),
            raw_value="",
            group=s.get("group", SIGNAL_TO_GROUP.get(s["source"], s["source"])),
        )
        for s in raw_signals
    ]
    provider, confidence = resolve_provider(signals)
    entry["provider"] = provider
    entry["classification_confidence"] = round(confidence * 100, 1)


async def classify_municipality(
    entry: dict[str, Any], semaphore: asyncio.Semaphore
) -> dict[str, Any]:
    """Classify a single municipality's email provider from its known domain."""
    async with semaphore:
        domain = entry.get("domain", "")
        result: dict[str, Any] = {
            "bfs": entry["bfs"],
            "name": entry["name"],
            "canton": entry.get("canton", ""),
            "domain": domain,
        }

        # Pass through resolve-level fields
        if "sources_detail" in entry:
            result["sources_detail"] = entry["sources_detail"]
        if "flags" in entry:
            result["resolve_flags"] = entry["flags"]

        if not domain:
            result["mx"] = []
            result["spf"] = ""
            result["provider"] = "unknown"
            return result

        mx = await lookup_mx(domain)
        spf = await lookup_spf(domain) if mx or domain else ""

        spf_resolved = await resolve_spf_includes(spf) if spf else ""
        mx_cnames = await resolve_mx_cnames(mx) if mx else {}
        mx_asns = await resolve_mx_asns(mx) if mx else set()
        if domain and mx:
            autodiscover, dkim = await asyncio.gather(
                lookup_autodiscover(domain),
                lookup_dkim_selectors(domain),
            )
        else:
            autodiscover = await lookup_autodiscover(domain) if domain else {}
            dkim = {}

        classification = classify_with_evidence(
            mx,
            spf,
            mx_cnames=mx_cnames,
            mx_asns=mx_asns or None,
            resolved_spf=spf_resolved or None,
            autodiscover=autodiscover or None,
            dkim=dkim or None,
        )

        result["mx"] = mx
        result["spf"] = spf
        result["provider"] = classification.provider
        result["classification_confidence"] = round(classification.confidence * 100, 1)
        result["classification_signals"] = [
            {
                "source": s.source,
                "provider": s.provider,
                "weight": s.weight,
                "detail": s.detail,
            }
            for s in classification.signals
        ]
        if spf_resolved and spf_resolved != spf:
            result["spf_resolved"] = spf_resolved
        if classification.gateway:
            result["gateway"] = classification.gateway
        if mx_cnames:
            result["mx_cnames"] = mx_cnames
        if mx_asns:
            result["mx_asns"] = sorted(mx_asns)
        if autodiscover:
            result["autodiscover"] = autodiscover
        if dkim:
            result["dkim"] = dkim
        return result


async def smtp_banner_batch(
    muni: dict[str, dict[str, Any]],
) -> int:
    """SMTP banner check for independent/unknown municipalities with MX records.

    Returns number of reclassified entries.
    """
    smtp_candidates = [
        m
        for m in muni.values()
        if m["provider"] in ("independent", "unknown") and m.get("mx")
    ]
    if not smtp_candidates:
        return 0

    mx_host_to_bfs: dict[str, list[str]] = {}
    for m in smtp_candidates:
        primary_mx = m["mx"][0]
        mx_host_to_bfs.setdefault(primary_mx, []).append(m["bfs"])

    print(
        f"\nSMTP banner check: {len(smtp_candidates)} entries, "
        f"{len(mx_host_to_bfs)} unique MX hosts..."
    )
    smtp_semaphore = asyncio.Semaphore(CONCURRENCY_SMTP)

    async def _fetch_banner(mx_host: str) -> tuple[str, dict[str, str]]:
        async with smtp_semaphore:
            res = await fetch_smtp_banner(mx_host)
            return mx_host, res

    banner_results = await asyncio.gather(
        *[_fetch_banner(host) for host in mx_host_to_bfs]
    )

    smtp_reclassified = 0
    for mx_host, result in banner_results:
        banner = result.get("banner", "")
        ehlo = result.get("ehlo", "")
        if not banner:
            continue
        provider = classify_from_smtp_banner(banner, ehlo)
        for bfs in mx_host_to_bfs[mx_host]:
            muni[bfs]["smtp_banner"] = banner
            if provider:
                smtp_signal = {
                    "source": "smtp",
                    "provider": provider,
                    "weight": SIGNAL_GROUP_WEIGHTS["smtp"],
                    "detail": f"SMTP banner matches {provider}",
                    "group": "smtp",
                }
                if "classification_signals" in muni[bfs]:
                    muni[bfs]["classification_signals"].append(smtp_signal)
            if provider and muni[bfs]["provider"] in ("independent", "unknown"):
                old = muni[bfs]["provider"]
                muni[bfs]["provider"] = provider
                smtp_reclassified += 1
                print(
                    f"  SMTP     {bfs:>5} {muni[bfs]['name']:<30} "
                    f"{old} -> {provider} ({mx_host})"
                )

    print(f"  SMTP reclassified: {smtp_reclassified}")
    return smtp_reclassified


async def tenant_check_batch(
    muni: dict[str, dict[str, Any]],
) -> int:
    """Microsoft tenant check for swiss-isp/independent/microsoft municipalities.

    Returns number of reclassified entries.
    """
    tenant_candidates = [
        m
        for m in muni.values()
        if m["provider"] in ("swiss-isp", "independent", "microsoft")
        and m.get("domain")
    ]
    if not tenant_candidates:
        return 0

    domain_to_bfs: dict[str, list[str]] = {}
    for m in tenant_candidates:
        domain_to_bfs.setdefault(m["domain"], []).append(m["bfs"])

    print(
        f"\nTenant check: {len(tenant_candidates)} entries, "
        f"{len(domain_to_bfs)} unique domains..."
    )
    tenant_semaphore = asyncio.Semaphore(CONCURRENCY_TENANT)

    async def _check_tenant(
        tc_client: httpx.AsyncClient, domain: str
    ) -> tuple[str, str | None]:
        async with tenant_semaphore:
            result = await check_microsoft_tenant(tc_client, domain)
            return domain, result

    async with httpx.AsyncClient() as tenant_client:
        tenant_results = await asyncio.gather(
            *[_check_tenant(tenant_client, d) for d in domain_to_bfs]
        )

    tenant_reclassified = 0
    tenant_confirmed = 0
    for domain, ns_type in tenant_results:
        if not ns_type:
            continue
        for bfs in domain_to_bfs[domain]:
            muni[bfs]["tenant_check"] = {"microsoft": ns_type}
            tenant_signal = {
                "source": "tenant",
                "provider": "microsoft",
                "weight": SIGNAL_GROUP_WEIGHTS["tenant"],
                "detail": f"MS tenant check: {ns_type}",
                "group": "tenant",
            }
            if "classification_signals" in muni[bfs]:
                muni[bfs]["classification_signals"].append(tenant_signal)
            if muni[bfs]["provider"] == "microsoft":
                tenant_confirmed += 1
            else:
                old = muni[bfs]["provider"]
                muni[bfs]["provider"] = "microsoft"
                tenant_reclassified += 1
                print(
                    f"  TENANT   {bfs:>5} {muni[bfs]['name']:<30} "
                    f"{old} -> microsoft ({ns_type})"
                )

    print(
        f"  Tenant reclassified: {tenant_reclassified}, confirmed: {tenant_confirmed}"
    )
    return tenant_reclassified


async def run(domains_path: Path, output_path: Path) -> None:
    with open(domains_path, encoding="utf-8") as f:
        domains_data = json.load(f)

    entries = domains_data["municipalities"]
    total = len(entries)

    print(f"Classifying {total} municipalities...")

    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [classify_municipality(e, semaphore) for e in entries.values()]

    results: dict[str, dict[str, Any]] = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results[result["bfs"]] = result
        done += 1
        if done % 50 == 0 or done == total:
            counts: dict[str, int] = {}
            for r in results.values():
                counts[r["provider"]] = counts.get(r["provider"], 0) + 1
            print(
                f"  [{done:4d}/{total}]  "
                f"MS={counts.get('microsoft', 0)}  "
                f"Google={counts.get('google', 0)}  "
                f"Infomaniak={counts.get('infomaniak', 0)}  "
                f"AWS={counts.get('aws', 0)}  "
                f"ISP={counts.get('swiss-isp', 0)}  "
                f"Indep={counts.get('independent', 0)}  "
                f"?={counts.get('unknown', 0)}"
            )

    # SMTP banner batch
    await smtp_banner_batch(results)

    # Recalculate confidence after SMTP signals
    for entry in results.values():
        recalculate_confidence(entry)

    # Tenant check batch
    await tenant_check_batch(results)

    # Recalculate confidence after tenant signals
    for entry in results.values():
        recalculate_confidence(entry)

    # Final counts
    counts = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1

    print(f"\n{'=' * 50}")
    print(f"RESULTS: {len(results)} municipalities classified")
    print(f"  Microsoft/Azure : {counts.get('microsoft', 0):>5}")
    print(f"  Google/GCP      : {counts.get('google', 0):>5}")
    print(f"  Infomaniak      : {counts.get('infomaniak', 0):>5}")
    print(f"  AWS             : {counts.get('aws', 0):>5}")
    print(f"  Swiss ISP       : {counts.get('swiss-isp', 0):>5}")
    print(f"  Independent     : {counts.get('independent', 0):>5}")
    print(f"  Unknown/No MX   : {counts.get('unknown', 0):>5}")
    print(f"{'=' * 50}")

    sorted_counts = dict(sorted(counts.items()))
    sorted_munis = dict(sorted(results.items(), key=lambda kv: int(kv[0])))

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "counts": sorted_counts,
        "municipalities": sorted_munis,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024
    print(f"\nWritten {output_path} ({size_kb:.0f} KB)")
