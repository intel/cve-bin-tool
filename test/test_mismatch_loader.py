import sqlite3
import tempfile
from pathlib import Path

from cve_bin_tool.mismatch_loader import setup_sqlite


def test_mismatch_loader():
    temp_db = None
    try:
        temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        temp_db_path = Path(temp_db.name)

        data_dir = Path(__file__).resolve().parent.parent / "mismatch_data"
        setup_sqlite(data_dir, temp_db_path)

        # Connect to the database and check if zstandard is present
        conn = sqlite3.connect(temp_db.name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM mismatch;")
        result = cursor.fetchall()

        expected = (
            "pkg:pypi/zstandard",
            "facebook",
        )
        assert expected in result
        conn.close()
    finally:
        if temp_db:
            temp_db.close()

        if temp_db_path.exists():
            temp_db_path.unlink()
