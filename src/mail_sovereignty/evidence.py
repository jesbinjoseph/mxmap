from dataclasses import dataclass, field


@dataclass
class Signal:
    source: str  # "mx", "mx_cname", "spf", "spf_resolved", "dkim", "autodiscover", "smtp", "tenant", "asn"
    provider: str | None  # detected provider, or None if no match
    weight: float  # 0.0–1.0 reflecting reliability of this signal type
    detail: str  # human-readable description
    raw_value: str  # the raw DNS data that triggered this
    group: str = ""  # signal group for deduplication (e.g. "spf", "mx")


@dataclass
class ClassificationResult:
    provider: str  # final label: "microsoft", "google", etc.
    confidence: float  # 0.0–1.0 overall confidence
    signals: list[Signal] = field(default_factory=list)
    gateway: str | None = None


# ── Group-based confidence model ──────────────────────────────────
# Each group's weight reflects how hard the signal is to mask.
# Weights sum to 1.0 so confidence = sum of matching group weights.

SIGNAL_GROUP_WEIGHTS: dict[str, float] = {
    "spf": 0.30,
    "mx": 0.25,
    "dkim": 0.18,
    "autodiscover": 0.09,
    "smtp": 0.06,
    "tenant": 0.06,
    "asn": 0.06,
}

# Map each signal source to its deduplication group
SIGNAL_TO_GROUP: dict[str, str] = {
    "mx": "mx",
    "mx_cname": "mx",
    "spf": "spf",
    "spf_resolved": "spf",
    "dkim": "dkim",
    "autodiscover": "autodiscover",
    "smtp": "smtp",
    "tenant": "tenant",
    "asn": "asn",
}

# Backward-compatible alias (maps every known source to a weight)
SIGNAL_WEIGHTS: dict[str, float] = {
    "mx": SIGNAL_GROUP_WEIGHTS["mx"],
    "mx_cname": SIGNAL_GROUP_WEIGHTS["mx"],
    "dkim": SIGNAL_GROUP_WEIGHTS["dkim"],
    "spf": SIGNAL_GROUP_WEIGHTS["spf"],
    "spf_resolved": SIGNAL_GROUP_WEIGHTS["spf"],
    "autodiscover_cname": SIGNAL_GROUP_WEIGHTS["autodiscover"],
    "autodiscover_srv": SIGNAL_GROUP_WEIGHTS["autodiscover"],
    "smtp": SIGNAL_GROUP_WEIGHTS["smtp"],
    "tenant": SIGNAL_GROUP_WEIGHTS["tenant"],
    "asn": SIGNAL_GROUP_WEIGHTS["asn"],
}


def resolve_provider(signals: list[Signal]) -> tuple[str, float]:
    """Aggregate weighted evidence per provider using group deduplication.

    Each signal group (spf, mx, dkim, …) is counted at most once per
    provider.  Confidence = sum of group weights for the winning provider,
    already in 0–1 because group weights sum to 1.0.
    """
    if not signals:
        return ("unknown", 0.0)

    # Per provider, track which groups matched (keep best weight per group)
    provider_groups: dict[str, dict[str, float]] = {}
    for signal in signals:
        if signal.provider is None:
            continue
        group = signal.group or SIGNAL_TO_GROUP.get(signal.source, signal.source)
        group_weight = SIGNAL_GROUP_WEIGHTS.get(group, 0.0)
        groups = provider_groups.setdefault(signal.provider, {})
        groups[group] = max(groups.get(group, 0.0), group_weight)

    if not provider_groups:
        return ("unknown", 0.0)

    # Sum group weights per provider
    provider_totals = {
        p: sum(weights.values()) for p, weights in provider_groups.items()
    }

    sorted_providers = sorted(provider_totals.items(), key=lambda x: -x[1])
    winner, winner_total = sorted_providers[0]

    confidence = min(1.0, winner_total)

    return (winner, confidence)


def has_conflict(signals: list[Signal], threshold: float = 0.05) -> bool:
    """Return True if top two providers are within threshold of each other."""
    provider_groups: dict[str, dict[str, float]] = {}
    for signal in signals:
        if signal.provider is None:
            continue
        group = signal.group or SIGNAL_TO_GROUP.get(signal.source, signal.source)
        group_weight = SIGNAL_GROUP_WEIGHTS.get(group, 0.0)
        groups = provider_groups.setdefault(signal.provider, {})
        groups[group] = max(groups.get(group, 0.0), group_weight)

    if len(provider_groups) < 2:
        return False

    totals = sorted(
        (sum(g.values()) for g in provider_groups.values()), reverse=True
    )
    return (totals[0] - totals[1]) < threshold
