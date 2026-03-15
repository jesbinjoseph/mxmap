from mail_sovereignty.evidence import (
    ClassificationResult,
    Signal,
    SIGNAL_GROUP_WEIGHTS,
    SIGNAL_TO_GROUP,
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
            weight=0.25,
            detail="MX hostname matches Microsoft",
            raw_value="mail.protection.outlook.com",
            group="mx",
        )
        assert s.source == "mx"
        assert s.provider == "microsoft"
        assert s.weight == 0.25
        assert s.group == "mx"

    def test_signal_group_defaults_to_empty(self):
        s = Signal("mx", "microsoft", 0.25, "test", "test")
        assert s.group == ""

    def test_classification_result_defaults(self):
        r = ClassificationResult(provider="microsoft", confidence=0.9)
        assert r.signals == []
        assert r.gateway is None

    def test_classification_result_with_signals(self):
        s = Signal("mx", "microsoft", 0.25, "test", "test", group="mx")
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
    def test_single_mx_signal(self):
        signals = [Signal("mx", "microsoft", 0.25, "test", "test", group="mx")]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.25

    def test_multiple_signals_agreeing(self):
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.55

    def test_three_signals_agreeing(self):
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
            Signal("dkim", "microsoft", 0.18, "test", "test", group="dkim"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.73

    def test_deduplication_spf_and_spf_resolved(self):
        """spf and spf_resolved are the same group — counted once."""
        signals = [
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
            Signal("spf_resolved", "microsoft", 0.30, "test", "test", group="spf"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.30  # not 0.60

    def test_deduplication_mx_and_mx_cname(self):
        """mx and mx_cname are the same group — counted once."""
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("mx_cname", "microsoft", 0.25, "test", "test", group="mx"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.25  # not 0.50

    def test_conflicting_signals_correct_winner(self):
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
            Signal("dkim", "google", 0.18, "test", "test", group="dkim"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.55

    def test_no_signals(self):
        provider, confidence = resolve_provider([])
        assert provider == "unknown"
        assert confidence == 0.0

    def test_signals_with_no_provider(self):
        signals = [Signal("asn", None, 0.06, "Swiss ISP", "test", group="asn")]
        provider, confidence = resolve_provider(signals)
        assert provider == "unknown"
        assert confidence == 0.0

    def test_gateway_with_backend_signals(self):
        signals = [
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
            Signal("dkim", "microsoft", 0.18, "test", "test", group="dkim"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.48

    def test_mixed_providers_weighted_resolution(self):
        signals = [
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
            Signal("dkim", "google", 0.18, "test", "test", group="dkim"),
            Signal("autodiscover", "microsoft", 0.09, "test", "test", group="autodiscover"),
        ]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"  # 0.30 + 0.09 = 0.39 > 0.18

    def test_group_fallback_from_source(self):
        """Signals without explicit group use SIGNAL_TO_GROUP mapping."""
        signals = [Signal("mx", "microsoft", 0.25, "test", "test")]
        provider, confidence = resolve_provider(signals)
        assert provider == "microsoft"
        assert confidence == 0.25


# ── has_conflict() ──────────────────────────────────────────────────


class TestHasConflict:
    def test_no_conflict_single_provider(self):
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
        ]
        assert has_conflict(signals) is False

    def test_conflict_close_weights(self):
        """Two providers with similar weight totals → conflict."""
        signals = [
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
            Signal("mx", "google", 0.25, "test", "test", group="mx"),
        ]
        assert has_conflict(signals) is True  # 0.30 - 0.25 = 0.05, equal to threshold

    def test_no_conflict_large_gap(self):
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("spf", "microsoft", 0.30, "test", "test", group="spf"),
            Signal("dkim", "google", 0.18, "test", "test", group="dkim"),
        ]
        # microsoft = 0.55, google = 0.18, gap = 0.37
        assert has_conflict(signals) is False

    def test_no_conflict_one_provider(self):
        signals = [Signal("mx", "microsoft", 0.25, "test", "test", group="mx")]
        assert has_conflict(signals) is False

    def test_empty_signals(self):
        assert has_conflict([]) is False

    def test_conflict_custom_threshold(self):
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("dkim", "google", 0.18, "test", "test", group="dkim"),
        ]
        # gap = 0.07, default threshold = 0.05, so no conflict
        assert has_conflict(signals) is False
        # with higher threshold, it's a conflict
        assert has_conflict(signals, threshold=0.10) is True

    def test_no_provider_signals_ignored(self):
        signals = [
            Signal("mx", "microsoft", 0.25, "test", "test", group="mx"),
            Signal("asn", None, 0.06, "test", "test", group="asn"),
        ]
        assert has_conflict(signals) is False


# ── SIGNAL_GROUP_WEIGHTS constants ─────────────────────────────────


class TestSignalGroupWeights:
    def test_weights_sum_to_one(self):
        assert abs(sum(SIGNAL_GROUP_WEIGHTS.values()) - 1.0) < 0.001

    def test_spf_is_highest(self):
        assert SIGNAL_GROUP_WEIGHTS["spf"] == 0.30

    def test_expected_groups_present(self):
        expected = {"spf", "mx", "dkim", "autodiscover", "smtp", "tenant", "asn"}
        assert set(SIGNAL_GROUP_WEIGHTS.keys()) == expected


# ── SIGNAL_WEIGHTS backward compatibility ──────────────────────────


class TestSignalWeights:
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

    def test_mx_and_mx_cname_same_weight(self):
        assert SIGNAL_WEIGHTS["mx"] == SIGNAL_WEIGHTS["mx_cname"]

    def test_spf_and_spf_resolved_same_weight(self):
        assert SIGNAL_WEIGHTS["spf"] == SIGNAL_WEIGHTS["spf_resolved"]


# ── SIGNAL_TO_GROUP mapping ────────────────────────────────────────


class TestSignalToGroup:
    def test_spf_resolved_maps_to_spf(self):
        assert SIGNAL_TO_GROUP["spf_resolved"] == "spf"

    def test_mx_cname_maps_to_mx(self):
        assert SIGNAL_TO_GROUP["mx_cname"] == "mx"

    def test_all_sources_mapped(self):
        expected = {"mx", "mx_cname", "spf", "spf_resolved", "dkim", "autodiscover", "smtp", "tenant", "asn"}
        assert set(SIGNAL_TO_GROUP.keys()) == expected
