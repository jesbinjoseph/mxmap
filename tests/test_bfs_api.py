from unittest.mock import AsyncMock, patch

from mail_sovereignty.bfs_api import (
    _extract_igod_district_names,
    _extract_igod_state_links,
    fetch_bfs_municipalities,
)

# Sample Indian municipality CSV
SAMPLE_CSV = """LGDCode,Name,State,Type
100100,Mumbai,Maharashtra,MC
100200,Delhi,Delhi,MC
100300,Bengaluru,Karnataka,MC
"""


def _patch_csv(tmp_path, content):
    """Write CSV to tmp_path and patch the path used by bfs_api."""
    csv_path = tmp_path / "indian_municipalities.csv"
    csv_path.write_text(content)
    # Patch Path(__file__) so that .parent.parent.parent / "indian_municipalities.csv" resolves to our tmp file
    fake_init = tmp_path / "src" / "mail_sovereignty" / "bfs_api.py"
    fake_init.parent.mkdir(parents=True, exist_ok=True)
    fake_init.touch()
    return patch("mail_sovereignty.bfs_api.__file__", str(fake_init))


class TestFetchBfsMunicipalities:
    async def test_loads_all_entries(self, tmp_path):
        with _patch_csv(tmp_path, SAMPLE_CSV):
            result = await fetch_bfs_municipalities()
        assert len(result) == 3
        assert "100100" in result
        assert "100200" in result
        assert "100300" in result

    async def test_output_format(self, tmp_path):
        with _patch_csv(tmp_path, SAMPLE_CSV):
            result = await fetch_bfs_municipalities()
        entry = result["100100"]
        assert entry["bfs"] == "100100"
        assert entry["name"] == "Mumbai"
        assert entry["canton"] == "Maharashtra"
        assert entry["type"] == "MC"

    async def test_empty_csv(self, tmp_path):
        with _patch_csv(tmp_path, "LGDCode,Name,State,Type\n"):
            result = await fetch_bfs_municipalities()
        assert result == {}

    async def test_include_igod_districts_adds_only_new_districts(self, tmp_path):
        district_csv = """LGDCode,Name,State,Type
100100,Mumbai,Maharashtra,District
"""
        igod_entries = [
            {"name": "Mumbai", "state": "Maharashtra", "type": "District"},
            {"name": "Pune", "state": "Maharashtra", "type": "District"},
        ]

        with (
            _patch_csv(tmp_path, district_csv),
            patch(
                "mail_sovereignty.bfs_api.fetch_igod_districts",
                new_callable=AsyncMock,
                return_value=igod_entries,
            ),
        ):
            result = await fetch_bfs_municipalities(include_igod_districts=True)

        names = {(row["name"], row["canton"], row["type"]) for row in result.values()}
        assert ("Mumbai", "Maharashtra", "District") in names
        assert ("Pune", "Maharashtra", "District") in names
        assert len(names) == 2


class TestIgodParsing:
    def test_extract_igod_state_links_from_states_page(self):
        html = """
        <li><a href="https://igod.gov.in/sg/MH/categories">Maharashtra</a></li>
        <li><a href="https://igod.gov.in/sg/AP/categories">Andhra Pradesh</a></li>
        """
        links = _extract_igod_state_links(html)
        assert links == [
            ("Maharashtra", "https://igod.gov.in/sg/MH/E042/organizations"),
            ("Andhra Pradesh", "https://igod.gov.in/sg/AP/E042/organizations"),
        ]

    def test_extract_igod_district_names_ignores_new_additions(self):
        html = """
        <div class="search-content">
          <a href="https://pune.gov.in" class="search-title">Pune</a>
          <div class="search-title">Markapuram</div>
        </div>
        <section class="in-focus-new-addition-outer">
          <a href="https://example.gov.in" class="search-title">Not A District</a>
        </section>
        """
        names = _extract_igod_district_names(html)
        assert names == ["Pune", "Markapuram"]
