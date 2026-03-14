import asyncio
import json
from unittest.mock import AsyncMock, patch

from mail_sovereignty.classify_pipeline import (
    classify_municipality,
    run,
    smtp_banner_batch,
    tenant_check_batch,
)


# ── classify_municipality() ──────────────────────────────────────────


class TestClassifyMunicipality:
    async def test_domain_with_mx(self):
        entry = {"bfs": "351", "name": "Bern", "canton": "Bern", "domain": "bern.ch"}
        sem = asyncio.Semaphore(10)

        with (
            patch(
                "mail_sovereignty.classify_pipeline.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.classify_pipeline.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_dkim_selectors",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await classify_municipality(entry, sem)

        assert result["provider"] == "microsoft"
        assert result["domain"] == "bern.ch"

    async def test_no_domain_is_unknown(self):
        entry = {"bfs": "999", "name": "Test", "canton": "Test", "domain": ""}
        sem = asyncio.Semaphore(10)

        result = await classify_municipality(entry, sem)

        assert result["provider"] == "unknown"
        assert result["mx"] == []

    async def test_gateway_detected(self):
        entry = {
            "bfs": "228",
            "name": "Turbenthal",
            "canton": "Zürich",
            "domain": "turbenthal.ch",
        }
        sem = asyncio.Semaphore(10)

        with (
            patch(
                "mail_sovereignty.classify_pipeline.lookup_mx",
                new_callable=AsyncMock,
                return_value=["customer.seppmail.cloud"],
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.classify_pipeline.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_dkim_selectors",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await classify_municipality(entry, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "seppmail"


# ── smtp_banner_batch() ──────────────────────────────────────────────


class TestSmtpBannerBatch:
    async def test_reclassifies_via_banner(self):
        muni = {
            "1000": {
                "bfs": "1000",
                "name": "SmtpTown",
                "canton": "Test",
                "domain": "smtptown.ch",
                "mx": ["mail.smtptown.ch"],
                "spf": "",
                "provider": "independent",
            },
        }

        with patch(
            "mail_sovereignty.classify_pipeline.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service ready",
                "ehlo": "250 ready",
            },
        ):
            count = await smtp_banner_batch(muni)

        assert count == 1
        assert muni["1000"]["provider"] == "microsoft"

    async def test_skips_when_no_candidates(self):
        muni = {
            "1000": {
                "bfs": "1000",
                "name": "Known",
                "provider": "microsoft",
                "mx": ["mail.protection.outlook.com"],
            },
        }

        count = await smtp_banner_batch(muni)
        assert count == 0

    async def test_deduplicates_mx_hosts(self):
        muni = {
            "2000": {
                "bfs": "2000",
                "name": "Town1",
                "provider": "independent",
                "mx": ["shared-mx.example.ch"],
            },
            "2001": {
                "bfs": "2001",
                "name": "Town2",
                "provider": "independent",
                "mx": ["shared-mx.example.ch"],
            },
        }

        with patch(
            "mail_sovereignty.classify_pipeline.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service",
                "ehlo": "250 ready",
            },
        ) as mock_fetch:
            count = await smtp_banner_batch(muni)
            assert mock_fetch.call_count == 1

        assert count == 2
        assert muni["2000"]["provider"] == "microsoft"
        assert muni["2001"]["provider"] == "microsoft"


# ── tenant_check_batch() ────────────────────────────────────────────


class TestTenantCheckBatch:
    async def test_reclassifies_swiss_isp(self):
        muni = {
            "1631": {
                "bfs": "1631",
                "name": "Glarus Süd",
                "provider": "swiss-isp",
                "domain": "glarussued.ch",
                "mx": ["ip17.gl.ch"],
            },
        }

        with patch(
            "mail_sovereignty.classify_pipeline.check_microsoft_tenant",
            new_callable=AsyncMock,
            return_value="Managed",
        ):
            count = await tenant_check_batch(muni)

        assert count == 1
        assert muni["1631"]["provider"] == "microsoft"
        assert muni["1631"]["tenant_check"] == {"microsoft": "Managed"}

    async def test_confirms_microsoft(self):
        muni = {
            "1002": {
                "bfs": "1002",
                "name": "SpfMicrosoft",
                "provider": "microsoft",
                "domain": "spftown.ch",
                "mx": ["mx.seppmail.cloud"],
            },
        }

        with patch(
            "mail_sovereignty.classify_pipeline.check_microsoft_tenant",
            new_callable=AsyncMock,
            return_value="Managed",
        ):
            count = await tenant_check_batch(muni)

        assert count == 0  # confirmed, not reclassified
        assert muni["1002"]["tenant_check"] == {"microsoft": "Managed"}

    async def test_no_tenant_no_change(self):
        muni = {
            "4000": {
                "bfs": "4000",
                "name": "NoTenant",
                "provider": "swiss-isp",
                "domain": "notenant.ch",
                "mx": ["mail.notenant.ch"],
            },
        }

        with patch(
            "mail_sovereignty.classify_pipeline.check_microsoft_tenant",
            new_callable=AsyncMock,
            return_value=None,
        ):
            count = await tenant_check_batch(muni)

        assert count == 0
        assert muni["4000"]["provider"] == "swiss-isp"
        assert "tenant_check" not in muni["4000"]


# ── run() ────────────────────────────────────────────────────────────


class TestClassifyPipelineRun:
    async def test_writes_output(self, tmp_path):
        domains_data = {
            "generated": "2025-01-01",
            "total": 1,
            "municipalities": {
                "351": {
                    "bfs": "351",
                    "name": "Bern",
                    "canton": "Bern",
                    "domain": "bern.ch",
                    "source": "wikidata",
                    "confidence": "high",
                },
            },
        }
        domains_path = tmp_path / "municipality_domains.json"
        domains_path.write_text(json.dumps(domains_data))

        with (
            patch(
                "mail_sovereignty.classify_pipeline.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.classify_pipeline.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.classify_pipeline.lookup_dkim_selectors",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "mail_sovereignty.classify_pipeline.check_microsoft_tenant",
                new_callable=AsyncMock,
                return_value="Managed",
            ),
        ):
            output = tmp_path / "data.json"
            await run(domains_path, output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert "351" in data["municipalities"]
        assert data["municipalities"]["351"]["provider"] == "microsoft"

    async def test_no_domain_is_unknown(self, tmp_path):
        domains_data = {
            "generated": "2025-01-01",
            "total": 1,
            "municipalities": {
                "9999": {
                    "bfs": "9999",
                    "name": "NoDomain",
                    "canton": "Test",
                    "domain": "",
                    "source": "none",
                    "confidence": "none",
                },
            },
        }
        domains_path = tmp_path / "municipality_domains.json"
        domains_path.write_text(json.dumps(domains_data))

        output = tmp_path / "data.json"
        await run(domains_path, output)

        data = json.loads(output.read_text())
        assert data["municipalities"]["9999"]["provider"] == "unknown"
