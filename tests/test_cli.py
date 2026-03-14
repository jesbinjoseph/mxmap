from pathlib import Path
from unittest.mock import AsyncMock, patch

from mail_sovereignty.cli import (
    classify_providers,
    resolve_domains,
    validate,
)


class TestCli:
    def test_resolve_domains(self):
        with (
            patch("mail_sovereignty.resolve.run", new_callable=AsyncMock) as mock_run,
            patch("sys.argv", ["resolve-domains"]),
        ):
            resolve_domains()
            mock_run.assert_called_once_with(
                Path("municipality_domains.json"),
                Path("overrides.json"),
                date=None,
            )

    def test_resolve_domains_with_date(self):
        with (
            patch("mail_sovereignty.resolve.run", new_callable=AsyncMock) as mock_run,
            patch("sys.argv", ["resolve-domains", "--date", "15-03-2026"]),
        ):
            resolve_domains()
            mock_run.assert_called_once_with(
                Path("municipality_domains.json"),
                Path("overrides.json"),
                date="15-03-2026",
            )

    def test_classify_providers(self):
        with patch(
            "mail_sovereignty.classify_pipeline.run", new_callable=AsyncMock
        ) as mock_run:
            classify_providers()
            mock_run.assert_called_once_with(
                Path("municipality_domains.json"), Path("data.json")
            )

    def test_validate(self):
        with patch("mail_sovereignty.validate.run") as mock_run:
            validate()
            mock_run.assert_called_once_with(
                Path("data.json"), Path("."), quality_gate=True
            )
