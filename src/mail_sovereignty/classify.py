from mail_sovereignty.constants import (
    FOREIGN_SENDER_KEYWORDS,
    GATEWAY_KEYWORDS,
    PROVIDER_KEYWORDS,
    SMTP_BANNER_KEYWORDS,
    SWISS_ISP_ASNS,
)
from mail_sovereignty.evidence import (
    ClassificationResult,
    Signal,
    SIGNAL_GROUP_WEIGHTS,
    SIGNAL_WEIGHTS,
    resolve_provider,
)


def classify_from_smtp_banner(banner: str, ehlo: str = "") -> str | None:
    """Classify provider from SMTP banner/EHLO. Returns provider or None."""
    if not banner and not ehlo:
        return None
    blob = f"{banner} {ehlo}".lower()
    for provider, keywords in SMTP_BANNER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def classify_from_dkim(dkim: dict[str, str] | None) -> str | None:
    """Classify provider from DKIM selector CNAME records."""
    if not dkim:
        return None
    # Return the first provider found (dict preserves insertion order)
    for provider in dkim:
        return provider
    return None


def classify_from_autodiscover(autodiscover: dict[str, str] | None) -> str | None:
    """Classify provider from autodiscover DNS records."""
    if not autodiscover:
        return None
    blob = " ".join(autodiscover.values()).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def detect_gateway(mx_records: list[str]) -> str | None:
    """Return gateway provider name if MX matches a known gateway, else None."""
    mx_blob = " ".join(mx_records).lower()
    for gateway, keywords in GATEWAY_KEYWORDS.items():
        if any(k in mx_blob for k in keywords):
            return gateway
    return None


def _check_spf_for_provider(spf_blob: str) -> str | None:
    """Check an SPF blob for hyperscaler keywords, return provider or None."""
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in spf_blob for k in keywords):
            return provider
    return None


def classify_with_evidence(
    mx_records: list[str],
    spf_record: str | None,
    mx_cnames: dict[str, str] | None = None,
    mx_asns: set[int] | None = None,
    resolved_spf: str | None = None,
    autodiscover: dict[str, str] | None = None,
    dkim: dict[str, str] | None = None,
) -> ClassificationResult:
    """Classify email provider with full evidence trail.

    Collects signals from all DNS sources, then resolves the winning provider
    via weighted evidence accumulation.
    """
    signals: list[Signal] = []
    mx_blob = " ".join(mx_records).lower()

    # ── MX hostname signals ──
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in mx_blob for k in keywords):
            signals.append(
                Signal(
                    source="mx",
                    provider=provider,
                    weight=SIGNAL_GROUP_WEIGHTS["mx"],
                    detail=f"MX hostname matches {provider}",
                    raw_value=mx_blob,
                    group="mx",
                )
            )

    # ── MX CNAME signals ──
    if mx_records and mx_cnames:
        cname_blob = " ".join(mx_cnames.values()).lower()
        for provider, keywords in PROVIDER_KEYWORDS.items():
            if any(k in cname_blob for k in keywords):
                signals.append(
                    Signal(
                        source="mx_cname",
                        provider=provider,
                        weight=SIGNAL_GROUP_WEIGHTS["mx"],
                        detail=f"MX CNAME target matches {provider}",
                        raw_value=cname_blob,
                        group="mx",
                    )
                )

    # ── SPF (direct) signals ──
    spf_blob = (spf_record or "").lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in spf_blob for k in keywords):
            signals.append(
                Signal(
                    source="spf",
                    provider=provider,
                    weight=SIGNAL_GROUP_WEIGHTS["spf"],
                    detail=f"SPF record mentions {provider}",
                    raw_value=spf_blob,
                    group="spf",
                )
            )

    # ── SPF (resolved) signals ──
    if resolved_spf:
        resolved_blob = resolved_spf.lower()
        for provider, keywords in PROVIDER_KEYWORDS.items():
            if any(k in resolved_blob for k in keywords):
                signals.append(
                    Signal(
                        source="spf_resolved",
                        provider=provider,
                        weight=SIGNAL_GROUP_WEIGHTS["spf"],
                        detail=f"Resolved SPF includes mention {provider}",
                        raw_value=resolved_blob,
                        group="spf",
                    )
                )

    # ── DKIM signals ──
    if dkim:
        dkim_provider = classify_from_dkim(dkim)
        if dkim_provider:
            signals.append(
                Signal(
                    source="dkim",
                    provider=dkim_provider,
                    weight=SIGNAL_GROUP_WEIGHTS["dkim"],
                    detail=f"DKIM CNAME delegates to {dkim_provider}",
                    raw_value=str(dkim),
                    group="dkim",
                )
            )

    # ── Autodiscover signals ──
    if autodiscover:
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            signals.append(
                Signal(
                    source="autodiscover",
                    provider=ad_provider,
                    weight=SIGNAL_GROUP_WEIGHTS["autodiscover"],
                    detail=f"Autodiscover points to {ad_provider}",
                    raw_value=str(autodiscover),
                    group="autodiscover",
                )
            )

    # ── ASN signals ──
    if mx_asns:
        matching_asns = mx_asns & SWISS_ISP_ASNS.keys()
        if matching_asns:
            isp_names = [SWISS_ISP_ASNS[asn] for asn in matching_asns]
            signals.append(
                Signal(
                    source="asn",
                    provider="swiss-isp",
                    weight=SIGNAL_GROUP_WEIGHTS["asn"],
                    detail=f"Swiss ISP: {', '.join(isp_names)}",
                    raw_value=str(sorted(matching_asns)),
                    group="asn",
                )
            )

    # ── Gateway detection ──
    gateway = detect_gateway(mx_records) if mx_records else None

    # ── Resolve provider from signals ──
    provider_signals = [s for s in signals if s.provider is not None]

    if provider_signals:
        provider, confidence = resolve_provider(signals)
    elif gateway:
        # Gateway with no provider signals behind it
        provider, confidence = "independent", 0.0
    elif not mx_records:
        provider, confidence = "unknown", 0.0
    else:
        provider, confidence = "independent", 0.0

    return ClassificationResult(
        provider=provider,
        confidence=confidence,
        signals=signals,
        gateway=gateway,
    )


def classify(
    mx_records: list[str],
    spf_record: str | None,
    mx_cnames: dict[str, str] | None = None,
    mx_asns: set[int] | None = None,
    resolved_spf: str | None = None,
    autodiscover: dict[str, str] | None = None,
    dkim: dict[str, str] | None = None,
) -> str:
    """Classify email provider based on MX, CNAME targets, and SPF.

    Wrapper around classify_with_evidence() for backward compatibility.
    """
    return classify_with_evidence(
        mx_records,
        spf_record,
        mx_cnames=mx_cnames,
        mx_asns=mx_asns,
        resolved_spf=resolved_spf,
        autodiscover=autodiscover,
        dkim=dkim,
    ).provider


def classify_from_mx(mx_records: list[str]) -> str | None:
    """Classify provider from MX records alone."""
    if not mx_records:
        return None
    blob = " ".join(mx_records).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return "independent"


def classify_from_spf(spf_record: str | None) -> str | None:
    """Classify provider from SPF record alone."""
    if not spf_record:
        return None
    blob = spf_record.lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def spf_mentions_providers(spf_record: str | None) -> set[str]:
    """Return set of providers mentioned in SPF (main + foreign senders)."""
    if not spf_record:
        return set()
    blob = spf_record.lower()
    found = set()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    for provider, keywords in FOREIGN_SENDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    return found
