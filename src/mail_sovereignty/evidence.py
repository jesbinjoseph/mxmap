from dataclasses import dataclass, field


@dataclass
class Signal:
    source: str  # "mx", "mx_cname", "spf", "spf_resolved", "dkim", "autodiscover", "smtp", "tenant", "asn"
    provider: str | None  # detected provider, or None if no match
    weight: float  # 0.0–1.0 reflecting reliability of this signal type
    detail: str  # human-readable description
    raw_value: str  # the raw DNS data that triggered this


@dataclass
class ClassificationResult:
    provider: str  # final label: "microsoft", "google", etc.
    confidence: float  # 0.0–1.0 overall confidence
    signals: list[Signal] = field(default_factory=list)
    gateway: str | None = None


# Signal weight constants
SIGNAL_WEIGHTS = {
    "mx": 1.0,
    "mx_cname": 0.95,
    "dkim": 0.85,
    "spf": 0.75,
    "spf_resolved": 0.65,
    "autodiscover_cname": 0.60,
    "autodiscover_srv": 0.55,
    "smtp": 0.50,
    "tenant": 0.50,
    "asn": 0.30,
}


def resolve_provider(signals: list[Signal]) -> tuple[str, float]:
    """Aggregate weighted evidence per provider, return (winner, confidence).

    Confidence = top provider's total weight / sum of max possible weight
    for signals present, clamped 0–1.
    """
    if not signals:
        return ("unknown", 0.0)

    provider_weights: dict[str, float] = {}
    for signal in signals:
        if signal.provider is not None:
            provider_weights[signal.provider] = (
                provider_weights.get(signal.provider, 0.0) + signal.weight
            )

    if not provider_weights:
        return ("unknown", 0.0)

    sorted_providers = sorted(provider_weights.items(), key=lambda x: -x[1])
    winner, winner_weight = sorted_providers[0]

    # Sum of max possible weight for all signal sources present
    total_possible = sum(
        signal.weight for signal in signals if signal.provider is not None
    )
    confidence = min(1.0, winner_weight / total_possible) if total_possible > 0 else 0.0

    return (winner, confidence)


def has_conflict(signals: list[Signal], threshold: float = 0.15) -> bool:
    """Return True if top two providers are within threshold of each other."""
    provider_weights: dict[str, float] = {}
    for signal in signals:
        if signal.provider is not None:
            provider_weights[signal.provider] = (
                provider_weights.get(signal.provider, 0.0) + signal.weight
            )

    if len(provider_weights) < 2:
        return False

    sorted_weights = sorted(provider_weights.values(), reverse=True)
    return (sorted_weights[0] - sorted_weights[1]) < threshold
