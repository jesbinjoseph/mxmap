"""Tests for posture probes (DMARC, DNSSEC, hosting)."""

from unittest.mock import MagicMock, patch

import pytest

from mail_sovereignty.geoip import AsnInfo
from mail_sovereignty.posture import (
    DmarcPosture,
    HostingPosture,
    _aggregate_tier,
    _classify_dmarc,
    _classify_hosting_asn,
    _parse_dmarc_record,
    probe_dmarc_posture,
    probe_hosting,
)


class TestParseDmarcRecord:
    def test_basic(self):
        tags = _parse_dmarc_record("v=DMARC1; p=reject; pct=100")
        assert tags == {"v": "DMARC1", "p": "reject", "pct": "100"}

    def test_lowercased_keys(self):
        tags = _parse_dmarc_record("v=DMARC1; P=Reject; PCT=50")
        assert tags["p"] == "Reject"
        assert tags["pct"] == "50"

    def test_whitespace_tolerant(self):
        tags = _parse_dmarc_record("  v=DMARC1 ;   p=none  ;  rua=mailto:a@b.c ")
        assert tags["p"] == "none"
        assert tags["rua"] == "mailto:a@b.c"

    def test_empty_segments_ignored(self):
        tags = _parse_dmarc_record("v=DMARC1;;; p=quarantine;;")
        assert tags["p"] == "quarantine"

    def test_first_occurrence_wins(self):
        tags = _parse_dmarc_record("v=DMARC1; p=reject; p=none")
        assert tags["p"] == "reject"


class TestClassifyDmarc:
    def test_missing(self):
        assert _classify_dmarc(present=False, policy=None, pct=None) == "missing"

    def test_present_no_policy_is_red(self):
        assert _classify_dmarc(present=True, policy=None, pct=None) == "red"

    def test_policy_none_is_red(self):
        assert _classify_dmarc(present=True, policy="none", pct=None) == "red"

    def test_policy_quarantine_is_amber(self):
        assert _classify_dmarc(present=True, policy="quarantine", pct=None) == "amber"

    def test_policy_reject_full_pct_is_green(self):
        assert _classify_dmarc(present=True, policy="reject", pct=100) == "green"
        assert _classify_dmarc(present=True, policy="reject", pct=None) == "green"

    def test_policy_reject_partial_pct_is_amber(self):
        assert _classify_dmarc(present=True, policy="reject", pct=50) == "amber"


class TestProbeDmarcPosture:
    def _mock_answer(self, txts: list[str]):
        rdatas = []
        for txt in txts:
            r = MagicMock()
            r.strings = [txt.encode("utf-8")]
            rdatas.append(r)
        answer = MagicMock()
        answer.__iter__ = lambda self: iter(rdatas)
        return answer

    @pytest.mark.asyncio
    async def test_missing_returns_missing_tier(self):
        with patch("mail_sovereignty.posture.resolve_robust", return_value=None):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.present is False
        assert posture.tier == "missing"

    @pytest.mark.asyncio
    async def test_reject_policy_is_green(self):
        answer = self._mock_answer(
            ["v=DMARC1; p=reject; rua=mailto:dmarc@example.gov.in"]
        )
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.present is True
        assert posture.policy == "reject"
        assert posture.subdomain_policy == "reject"  # inherits p=
        assert posture.tier == "green"
        assert posture.rua == ["mailto:dmarc@example.gov.in"]
        assert posture.raw.startswith("v=DMARC1")

    @pytest.mark.asyncio
    async def test_quarantine_is_amber(self):
        answer = self._mock_answer(["v=DMARC1; p=quarantine"])
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.tier == "amber"

    @pytest.mark.asyncio
    async def test_reject_with_partial_pct_is_amber(self):
        answer = self._mock_answer(["v=DMARC1; p=reject; pct=25"])
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.pct == 25
        assert posture.tier == "amber"

    @pytest.mark.asyncio
    async def test_none_policy_is_red(self):
        answer = self._mock_answer(["v=DMARC1; p=none"])
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.tier == "red"

    @pytest.mark.asyncio
    async def test_subdomain_policy_overrides(self):
        answer = self._mock_answer(["v=DMARC1; p=reject; sp=none"])
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.policy == "reject"
        assert posture.subdomain_policy == "none"

    @pytest.mark.asyncio
    async def test_non_dmarc_txt_ignored(self):
        """TXT records that aren't DMARC (e.g. SPF) must not fool the probe."""
        answer = self._mock_answer(["v=spf1 include:example.com -all"])
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.present is False
        assert posture.tier == "missing"

    @pytest.mark.asyncio
    async def test_multiple_rua_parsed(self):
        answer = self._mock_answer(
            ["v=DMARC1; p=reject; rua=mailto:a@b.c, mailto:d@e.f"]
        )
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.rua == ["mailto:a@b.c", "mailto:d@e.f"]

    @pytest.mark.asyncio
    async def test_present_but_no_p_tag(self):
        """Record present but malformed (missing p=) → red."""
        answer = self._mock_answer(["v=DMARC1; rua=mailto:a@b.c"])
        with patch("mail_sovereignty.posture.resolve_robust", return_value=answer):
            posture = await probe_dmarc_posture("example.gov.in")
        assert posture.present is True
        assert posture.policy is None
        assert posture.tier == "red"


class TestDmarcPostureModel:
    def test_default_empty_lists(self):
        p = DmarcPosture(present=False, tier="missing")
        assert p.rua == []
        assert p.ruf == []

    def test_frozen(self):
        p = DmarcPosture(present=True, policy="reject", tier="green")
        with pytest.raises(Exception):
            p.tier = "amber"  # type: ignore[misc]


class TestClassifyHostingAsn:
    def test_nic_is_india_govt(self):
        assert _classify_hosting_asn(4758) == "india-govt"

    def test_microsoft_is_foreign_cloud(self):
        assert _classify_hosting_asn(8075) == "foreign-cloud"

    def test_google_is_foreign_cloud(self):
        assert _classify_hosting_asn(15169) == "foreign-cloud"

    def test_airtel_is_india_private(self):
        assert _classify_hosting_asn(9498) == "india-private"

    def test_unknown_asn_is_foreign_other(self):
        assert _classify_hosting_asn(999999) == "foreign-other"


class TestAggregateTier:
    def test_empty_is_unknown(self):
        assert _aggregate_tier([]) == "unknown"

    def test_single_tier_wins(self):
        assert _aggregate_tier(["foreign-cloud"]) == "foreign-cloud"

    def test_govt_beats_everything(self):
        assert (
            _aggregate_tier(["foreign-cloud", "india-govt", "foreign-other"])
            == "india-govt"
        )

    def test_private_beats_foreign(self):
        assert _aggregate_tier(["foreign-cloud", "india-private"]) == "india-private"

    def test_foreign_cloud_beats_foreign_other(self):
        assert _aggregate_tier(["foreign-other", "foreign-cloud"]) == "foreign-cloud"


class TestProbeHosting:
    def _a_answer(self, ips: list[str]):
        rdatas = [MagicMock(__str__=lambda self, ip=ip: ip) for ip in ips]
        a = MagicMock()
        a.__iter__ = lambda self: iter(rdatas)
        return a

    @pytest.mark.asyncio
    async def test_no_mx_returns_unknown(self):
        posture = await probe_hosting([])
        assert posture.tier == "unknown"
        assert posture.asns == []
        assert posture.countries == []

    @pytest.mark.asyncio
    async def test_nic_mx_is_india_govt(self):
        a_answer = self._a_answer(["164.100.100.1"])
        asn_info = AsnInfo(asn=4758, country="IN", prefix="164.100.0.0/16")

        with (
            patch("mail_sovereignty.posture.resolve_robust", return_value=a_answer),
            patch("mail_sovereignty.posture.lookup_asn", return_value=asn_info),
        ):
            posture = await probe_hosting(["mx1.gov.in"])

        assert posture.tier == "india-govt"
        assert posture.countries == ["IN"]
        assert len(posture.asns) == 1
        assert posture.asns[0].asn == 4758
        assert posture.asns[0].country == "IN"
        assert "NIC" in posture.asns[0].name

    @pytest.mark.asyncio
    async def test_microsoft_mx_is_foreign_cloud(self):
        a_answer = self._a_answer(["52.96.0.1"])
        asn_info = AsnInfo(asn=8075, country="US", prefix="52.96.0.0/14")

        with (
            patch("mail_sovereignty.posture.resolve_robust", return_value=a_answer),
            patch("mail_sovereignty.posture.lookup_asn", return_value=asn_info),
        ):
            posture = await probe_hosting(["example-com.mail.protection.outlook.com"])

        assert posture.tier == "foreign-cloud"
        assert posture.countries == ["US"]
        assert posture.asns[0].asn == 8075

    @pytest.mark.asyncio
    async def test_multi_mx_picks_highest_sovereignty(self):
        """Mixed NIC + MS deployment is classified as sovereign."""
        a_answer_a = self._a_answer(["164.100.100.1"])
        a_answer_b = self._a_answer(["52.96.0.1"])
        nic_info = AsnInfo(asn=4758, country="IN", prefix="164.100.0.0/16")
        ms_info = AsnInfo(asn=8075, country="US", prefix="52.96.0.0/14")

        async def fake_resolve(host, _rtype):
            if "gov.in" in host:
                return a_answer_a
            return a_answer_b

        async def fake_lookup(ip):
            return nic_info if ip.startswith("164.") else ms_info

        with (
            patch("mail_sovereignty.posture.resolve_robust", side_effect=fake_resolve),
            patch("mail_sovereignty.posture.lookup_asn", side_effect=fake_lookup),
        ):
            posture = await probe_hosting(
                ["mx.gov.in", "fallback.mail.protection.outlook.com"]
            )

        assert posture.tier == "india-govt"
        assert set(posture.countries) == {"IN", "US"}
        assert {a.asn for a in posture.asns} == {4758, 8075}

    @pytest.mark.asyncio
    async def test_no_a_record_returns_unknown(self):
        with patch("mail_sovereignty.posture.resolve_robust", return_value=None):
            posture = await probe_hosting(["nonexistent.example"])
        assert posture.tier == "unknown"

    @pytest.mark.asyncio
    async def test_cymru_miss_returns_unknown(self):
        a_answer = self._a_answer(["203.0.113.1"])
        with (
            patch("mail_sovereignty.posture.resolve_robust", return_value=a_answer),
            patch("mail_sovereignty.posture.lookup_asn", return_value=None),
        ):
            posture = await probe_hosting(["obscure.example"])
        assert posture.tier == "unknown"
        assert posture.asns == []


class TestHostingPostureModel:
    def test_defaults(self):
        p = HostingPosture(tier="unknown")
        assert p.asns == []
        assert p.countries == []

    def test_frozen(self):
        p = HostingPosture(tier="india-govt")
        with pytest.raises(Exception):
            p.tier = "foreign-cloud"  # type: ignore[misc]
