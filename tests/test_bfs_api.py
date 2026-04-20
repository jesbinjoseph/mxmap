from unittest.mock import patch

from mail_sovereignty.bfs_api import fetch_bfs_municipalities

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
