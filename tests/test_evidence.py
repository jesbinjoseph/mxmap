from mail_sovereignty.evidence import (
    ClassificationResult,
    Signal,
    SIGNAL_WEIGHTS,
    has_conflict,
    resolve_provider,
)


# ── Signal and ClassificationResult construction ────────────────────


class TestDataclasses:
    def test_signal_construction(self):
        s = Signal(
            source="mx",
            provider="microsoft",
            weight=1.0,
            detail="MX hostname matches Microsoft",
            raw_value="mail.protection.outlook.com",
        )
        assert s.source == "mx"
        assert s.provider == "microsoft"
        assert s.weight == 1.0

    def test_classification_result_defaults(self):
        r = ClassificationResult(provider="microsoft", confidence=0.9)
        assert r.signals == []
        assert r.gateway is None

    def test_classification_result_with_signals(self):
        s = Signal("mx", "microsoft", 1.0, "test", "test")
        r = ClassificationResult(
            provider="microsoft",
            confidence=0.9,
            signals=[s],
            gateway="seppmail",
        )
        assert len(r.signals) == 1
        assert r.gateway == "seppmail"


# ── resolve_provider() ──────────────────────────────────────────────


class TestResolveProvider:
    def test_single_strong_signal(self):
        signals = [Signal("mx", "microsoft", 1.0, "test", "test")]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 1.0

    def test_multiple_signals_agreeing(self):
        signals = [
            Signal("mx", "microsoft", 1.0, "test", "test"),
            Signal("spf", "microsoft", 0.75, "test", "test"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 1.0

    def test_conflicting_signals_correct_winner(self):
        signals = [
            Signal("mx", "microsoft", 1.0, "test", "test"),
            Signal("dkim", "google", 0.85, "test", "test"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence < 1.0

    def test_no_signals(self):
        provider, confidence = resolve_provider([])
        assert provider == "unknown"
        assert confidence == 0.0

    def test_signals_with_no_provider(self):
        signals = [Signal("asn", None, 0.3, "Swiss ISP", "test")]
        provider, confidence = resolve_provider(signals)
        assert provider == "unknown"
        assert confidence == 0.0

    def test_gateway_with_backend_signals(self):
        signals = [
            Signal("spf", "microsoft", 0.75, "test", "test"),
            Signal("dkim", "microsoft", 0.85, "test", "test"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 1.0

    def test_mixed_providers_weighted_resolution(self):
        signals = [
            Signal("spf", "microsoft", 0.75, "test", "test"),
            Signal("dkim", "google", 0.85, "test", "test"),
            Signal("autodiscover", "microsoft", 0.60, "test", "test"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"  # 0.75 + 0.60 = 1.35 > 0.85


# ── has_conflict() ──────────────────────────────────────────────────


class TestHasConflict:
    def test_no_conflict_single_provider(self):
        signals = [
            Signal("mx", "microsoft", 1.0, "test", "test"),
            Signal("spf", "microsoft", 0.75, "test", "test"),
        ]
        assert has_conflict(signals) is False

    def test_conflict_close_weights(self):
        signals = [
            Signal("spf", "microsoft", 0.75, "test", "test"),
            Signal("dkim", "google", 0.85, "test", "test"),
        ]
        assert has_conflict(signals) is True

    def test_no_conflict_large_gap(self):
        signals = [
            Signal("mx", "microsoft", 1.0, "test", "test"),
            Signal("asn", None, 0.3, "test", "test"),
        ]
        assert has_conflict(signals) is False

    def test_no_conflict_one_provider(self):
        signals = [Signal("mx", "microsoft", 1.0, "test", "test")]
        assert has_conflict(signals) is False

    def test_empty_signals(self):
        assert has_conflict([]) is False

    def test_conflict_custom_threshold(self):
        signals = [
            Signal("mx", "microsoft", 1.0, "test", "test"),
            Signal("dkim", "google", 0.85, "test", "test"),
        ]
        # gap = 0.15 which equals default threshold, so no conflict
        assert has_conflict(signals) is False
        # with higher threshold, it's a conflict
        assert has_conflict(signals, threshold=0.20) is True

    def test_no_provider_signals_ignored(self):
        signals = [
            Signal("mx", "microsoft", 1.0, "test", "test"),
            Signal("asn", None, 0.3, "test", "test"),
        ]
        assert has_conflict(signals) is False


# ── SIGNAL_WEIGHTS constants ────────────────────────────────────────


class TestSignalWeights:
    def test_mx_is_highest(self):
        assert SIGNAL_WEIGHTS["mx"] == 1.0

    def test_all_weights_between_0_and_1(self):
        for weight in SIGNAL_WEIGHTS.values():
            assert 0.0 < weight <= 1.0

    def test_expected_sources_present(self):
        expected = {
            "mx",
            "mx_cname",
            "dkim",
            "spf",
            "spf_resolved",
            "autodiscover_cname",
            "autodiscover_srv",
            "smtp",
            "tenant",
            "asn",
        }
        assert set(SIGNAL_WEIGHTS.keys()) == expected
