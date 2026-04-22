"""Tests for geoip.lookup_asn (Team Cymru DNS wrapper)."""

from unittest.mock import MagicMock, patch

import pytest

from mail_sovereignty.geoip import AsnInfo, lookup_asn


def _answer(txts: list[str]):
    rdatas = []
    for t in txts:
        r = MagicMock()
        r.strings = [t.encode("utf-8")]
        rdatas.append(r)
    a = MagicMock()
    a.__iter__ = lambda self: iter(rdatas)
    return a


class TestLookupAsn:
    @pytest.mark.asyncio
    async def test_valid_record_parses(self):
        with patch(
            "mail_sovereignty.geoip.resolve_robust",
            return_value=_answer(["4758 | 164.100.0.0/16 | IN | apnic | 1996-12-01"]),
        ):
            info = await lookup_asn("164.100.100.1")
        assert info == AsnInfo(asn=4758, country="IN", prefix="164.100.0.0/16")

    @pytest.mark.asyncio
    async def test_no_answer_returns_none(self):
        with patch("mail_sovereignty.geoip.resolve_robust", return_value=None):
            info = await lookup_asn("8.8.8.8")
        assert info is None

    @pytest.mark.asyncio
    async def test_empty_ip_returns_none(self):
        info = await lookup_asn("")
        assert info is None

    @pytest.mark.asyncio
    async def test_ipv6_skipped(self):
        info = await lookup_asn("2001:4860:4860::8888")
        assert info is None

    @pytest.mark.asyncio
    async def test_malformed_record_returns_none(self):
        with patch(
            "mail_sovereignty.geoip.resolve_robust",
            return_value=_answer(["not-an-asn"]),
        ):
            info = await lookup_asn("8.8.8.8")
        assert info is None

    @pytest.mark.asyncio
    async def test_multi_origin_asn_takes_first(self):
        """Cymru sometimes returns '15169 6939 | ...' for multi-origin prefixes."""
        with patch(
            "mail_sovereignty.geoip.resolve_robust",
            return_value=_answer(["15169 6939 | 8.8.8.0/24 | US | arin | 2014"]),
        ):
            info = await lookup_asn("8.8.8.8")
        assert info is not None
        assert info.asn == 15169
        assert info.country == "US"

    @pytest.mark.asyncio
    async def test_empty_country_normalized(self):
        with patch(
            "mail_sovereignty.geoip.resolve_robust",
            return_value=_answer(["64512 | 10.0.0.0/8 |  | other | 1996"]),
        ):
            info = await lookup_asn("10.0.0.1")
        assert info is not None
        assert info.country == ""

    @pytest.mark.asyncio
    async def test_uppercases_country(self):
        with patch(
            "mail_sovereignty.geoip.resolve_robust",
            return_value=_answer(["4758 | 164.100.0.0/16 | in | apnic | 1996"]),
        ):
            info = await lookup_asn("164.100.1.1")
        assert info is not None
        assert info.country == "IN"
