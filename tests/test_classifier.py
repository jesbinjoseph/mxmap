"""Tests for classifier: _aggregate, classify, and classify_many."""

from unittest.mock import AsyncMock, patch

import pytest

from mail_sovereignty.classifier import _aggregate, classify, classify_many
from mail_sovereignty.models import (
    Evidence,
    Provider,
    SignalKind,
)
from mail_sovereignty.probes import WEIGHTS


def _ev(kind: SignalKind, provider: Provider, weight: float | None = None) -> Evidence:
    if weight is None:
        weight = WEIGHTS[kind]
    return Evidence(
        kind=kind, provider=provider, weight=weight, detail="test", raw="test"
    )


def _patch_all_probes(**overrides):
    """Return a context manager that patches all probes with defaults (empty lists)."""
    probe_names = [
        "probe_mx",
        "probe_spf",
        "probe_dkim",
        "probe_dmarc",
        "probe_autodiscover",
        "probe_cname_chain",
        "probe_smtp",
        "probe_tenant",
        "probe_asn",
        "probe_txt_verification",
    ]
    patches = {}
    for name in probe_names:
        patches[name] = overrides.get(name, [])

    # Also handle detect_gateway
    gateway = overrides.get("detect_gateway", None)

    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with (
            patch(
                "mail_sovereignty.classifier.probe_mx",
                new_callable=AsyncMock,
                return_value=patches["probe_mx"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_spf",
                new_callable=AsyncMock,
                return_value=patches["probe_spf"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dkim",
                new_callable=AsyncMock,
                return_value=patches["probe_dkim"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dmarc",
                new_callable=AsyncMock,
                return_value=patches["probe_dmarc"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_autodiscover",
                new_callable=AsyncMock,
                return_value=patches["probe_autodiscover"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_cname_chain",
                new_callable=AsyncMock,
                return_value=patches["probe_cname_chain"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_smtp",
                new_callable=AsyncMock,
                return_value=patches["probe_smtp"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_tenant",
                new_callable=AsyncMock,
                return_value=patches["probe_tenant"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_asn",
                new_callable=AsyncMock,
                return_value=patches["probe_asn"],
            ),
            patch(
                "mail_sovereignty.classifier.probe_txt_verification",
                new_callable=AsyncMock,
                return_value=patches["probe_txt_verification"],
            ),
            patch("mail_sovereignty.classifier.detect_gateway", return_value=gateway),
        ):
            yield

    return _ctx()


class TestAggregate:
    def test_empty(self):
        result = _aggregate([])
        assert result.provider == Provider.INDEPENDENT
        assert result.confidence == 0.0
        assert result.evidence == []
        assert result.gateway is None

    def test_single_signal(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        assert result.confidence == WEIGHTS[SignalKind.MX]

    def test_multi_signal_same_provider(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.DKIM, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        expected = (
            WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.SPF] + WEIGHTS[SignalKind.DKIM]
        )
        assert result.confidence == pytest.approx(expected)

    def test_deduplication_by_kind(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.MX, Provider.MS365),  # duplicate kind
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        assert result.confidence == pytest.approx(WEIGHTS[SignalKind.MX])

    def test_conflict_higher_score_wins(self):
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.SPF, Provider.MS365),
            _ev(SignalKind.DMARC, Provider.GOOGLE),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        expected = WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.SPF]
        assert result.confidence == pytest.approx(expected)

    def test_confidence_capped_at_1(self):
        evidence = [_ev(kind, Provider.MS365) for kind in SignalKind]
        result = _aggregate(evidence)
        assert result.confidence == 1.0

    def test_independent_evidence_ignored(self):
        evidence = [_ev(SignalKind.MX, Provider.INDEPENDENT)]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        assert result.confidence == 0.0

    def test_gateway_passthrough(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence, gateway="seppmail")
        assert result.gateway == "seppmail"
        assert result.provider == Provider.MS365

    def test_gateway_none_by_default(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence)
        assert result.gateway is None

    def test_tenant_confirmation_only_discarded(self):
        """Tenant evidence without primary signals should be discarded."""
        evidence = [
            _ev(SignalKind.TENANT, Provider.MS365),
            # No MX, SPF, or DKIM for MS365
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INDEPENDENT
        assert result.confidence == 0.0

    def test_tenant_confirmation_with_primary(self):
        """Tenant evidence with primary signals should be counted."""
        evidence = [
            _ev(SignalKind.MX, Provider.MS365),
            _ev(SignalKind.TENANT, Provider.MS365),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.MS365
        expected = WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.TENANT]
        assert result.confidence == pytest.approx(expected)

    def test_tenant_discarded_when_different_provider_has_primary(self):
        """MS365 tenant should be discarded when only Google has primary signals."""
        evidence = [
            _ev(SignalKind.MX, Provider.GOOGLE),
            _ev(SignalKind.TENANT, Provider.MS365),  # no MS365 primary
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.GOOGLE
        assert result.confidence == pytest.approx(WEIGHTS[SignalKind.MX])

    def test_infomaniak_classification(self):
        evidence = [
            _ev(SignalKind.MX, Provider.INFOMANIAK),
            _ev(SignalKind.SPF, Provider.INFOMANIAK),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.INFOMANIAK

    def test_swiss_isp_classification(self):
        evidence = [
            _ev(SignalKind.ASN, Provider.SWISS_ISP),
        ]
        result = _aggregate(evidence)
        assert result.provider == Provider.SWISS_ISP
        assert result.confidence == pytest.approx(WEIGHTS[SignalKind.ASN])

    def test_mx_hosts_passthrough(self):
        evidence = [_ev(SignalKind.MX, Provider.MS365)]
        result = _aggregate(evidence, mx_hosts=["mx1.example.com"])
        assert result.mx_hosts == ["mx1.example.com"]

    def test_mx_hosts_default_empty(self):
        result = _aggregate([])
        assert result.mx_hosts == []


class TestClassify:
    async def test_ms365_scenario(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="example-com.mail.protection.outlook.com",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_spf=spf_ev):
            result = await classify("example.com")

        assert result.provider == Provider.MS365
        expected = WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.SPF]
        assert result.confidence == pytest.approx(expected)

    async def test_google_scenario(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.GOOGLE,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="aspmx.l.google.com",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.GOOGLE,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]
        dkim_ev = [
            Evidence(
                kind=SignalKind.DKIM,
                provider=Provider.GOOGLE,
                weight=WEIGHTS[SignalKind.DKIM],
                detail="DKIM match",
                raw="google",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_spf=spf_ev, probe_dkim=dkim_ev):
            result = await classify("example.com")

        assert result.provider == Provider.GOOGLE
        expected = (
            WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.SPF] + WEIGHTS[SignalKind.DKIM]
        )
        assert result.confidence == pytest.approx(expected)

    async def test_independent_scenario(self):
        with _patch_all_probes():
            result = await classify("example.com")

        assert result.provider == Provider.INDEPENDENT
        assert result.confidence == 0.0

    async def test_gateway_scenario(self):
        """MX=seppmail, SPF=outlook → MS365 with gateway="seppmail"."""
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="mx.seppmail.cloud",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]

        with _patch_all_probes(
            probe_mx=mx_ev,
            probe_spf=spf_ev,
            detect_gateway="seppmail",
        ):
            result = await classify("example.com")

        assert result.provider == Provider.MS365
        assert result.gateway == "seppmail"

    async def test_infomaniak_scenario(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.INFOMANIAK,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="mxpool.infomaniak.com",
            )
        ]
        spf_ev = [
            Evidence(
                kind=SignalKind.SPF,
                provider=Provider.INFOMANIAK,
                weight=WEIGHTS[SignalKind.SPF],
                detail="SPF match",
                raw="v=spf1",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_spf=spf_ev):
            result = await classify("example.com")

        assert result.provider == Provider.INFOMANIAK

    async def test_swiss_isp_scenario(self):
        """Swiss ASN, no hyperscaler signals → SWISS_ISP."""
        asn_ev = [
            Evidence(
                kind=SignalKind.ASN,
                provider=Provider.SWISS_ISP,
                weight=WEIGHTS[SignalKind.ASN],
                detail="ASN 3303 is Swiss ISP: Swisscom",
                raw="3303",
            )
        ]

        with _patch_all_probes(probe_asn=asn_ev):
            result = await classify("example.com")

        assert result.provider == Provider.SWISS_ISP

    async def test_tenant_confirmation_only_in_classify(self):
        """Domain with Swiss ISP MX + positive M365 tenant → must NOT classify as MS365."""
        asn_ev = [
            Evidence(
                kind=SignalKind.ASN,
                provider=Provider.SWISS_ISP,
                weight=WEIGHTS[SignalKind.ASN],
                detail="ASN is Swiss ISP",
                raw="3303",
            )
        ]
        tenant_ev = [
            Evidence(
                kind=SignalKind.TENANT,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.TENANT],
                detail="MS365 tenant detected",
                raw="Managed",
            )
        ]

        with _patch_all_probes(probe_asn=asn_ev, probe_tenant=tenant_ev):
            result = await classify("example.com")

        # Tenant evidence for MS365 should be discarded (no MS365 primary signals)
        assert result.provider != Provider.MS365
        assert result.provider == Provider.SWISS_ISP

    async def test_tenant_confirmation_with_ms365_primary(self):
        """Domain with MX→outlook + positive M365 tenant → MS365 with boosted confidence."""
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="example-com.mail.protection.outlook.com",
            )
        ]
        tenant_ev = [
            Evidence(
                kind=SignalKind.TENANT,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.TENANT],
                detail="MS365 tenant detected",
                raw="Managed",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev, probe_tenant=tenant_ev):
            result = await classify("example.com")

        assert result.provider == Provider.MS365
        expected = WEIGHTS[SignalKind.MX] + WEIGHTS[SignalKind.TENANT]
        assert result.confidence == pytest.approx(expected)

    async def test_classify_passes_mx_hosts_to_cname_chain(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="custom-mx.example.com",
            )
        ]
        mock_cname = AsyncMock(return_value=[])

        with (
            patch(
                "mail_sovereignty.classifier.probe_mx",
                new_callable=AsyncMock,
                return_value=mx_ev,
            ),
            patch(
                "mail_sovereignty.classifier.probe_spf",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dkim",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_dmarc",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_autodiscover",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("mail_sovereignty.classifier.probe_cname_chain", mock_cname),
            patch(
                "mail_sovereignty.classifier.probe_smtp",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_tenant",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_asn",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.classifier.probe_txt_verification",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("mail_sovereignty.classifier.detect_gateway", return_value=None),
        ):
            await classify("example.com")

        mock_cname.assert_called_once()
        call_args = mock_cname.call_args
        assert call_args[0][1] == ["custom-mx.example.com"]

    async def test_classify_populates_mx_hosts(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="example-com.mail.protection.outlook.com",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev):
            result = await classify("example.com")

        assert result.mx_hosts == ["example-com.mail.protection.outlook.com"]


class TestClassifyMany:
    async def test_yields_all_domains(self):
        mx_ev = [
            Evidence(
                kind=SignalKind.MX,
                provider=Provider.MS365,
                weight=WEIGHTS[SignalKind.MX],
                detail="MX match",
                raw="mx.outlook.com",
            )
        ]

        with _patch_all_probes(probe_mx=mx_ev):
            results = []
            async for domain, result in classify_many(["a.com", "b.com"]):
                results.append((domain, result))

        domains = {d for d, _ in results}
        assert domains == {"a.com", "b.com"}
        for _, r in results:
            assert r.provider == Provider.MS365

    async def test_empty_domains(self):
        results = []
        async for domain, result in classify_many([]):
            results.append((domain, result))
        assert results == []

    async def test_respects_concurrency(self):
        with _patch_all_probes():
            results = []
            async for domain, result in classify_many(["a.com"], max_concurrency=1):
                results.append((domain, result))
        assert len(results) == 1
