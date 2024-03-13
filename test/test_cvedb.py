# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import shutil
import tempfile
from test.utils import EXTERNAL_SYSTEM, LONG_TESTS

import pytest

from cve_bin_tool import cvedb
from cve_bin_tool.cli import main
from cve_bin_tool.data_sources import nvd_source


class TestCVEDB:
    @classmethod
    def setup_class(cls):
        cls.nvd = nvd_source.NVD_Source(nvd_type="json")
        cachedir = tempfile.mkdtemp(prefix="cvedb-")
        cls.exported_data = tempfile.mkdtemp(prefix="exported-data-")
        cls.cvedb = cvedb.CVEDB(sources=[cls.nvd], cachedir=cachedir)
        cls.nvd.cachedir = cachedir

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.nvd.cachedir)
        shutil.rmtree(cls.exported_data)

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM(), reason="Skipping NVD calls due to rate limits"
    )
    async def test_refresh_nvd_json(self):
        await self.cvedb.refresh()
        years = self.nvd.nvd_years()
        for year in range(2002, datetime.datetime.now().year):
            assert year in years, f"Missing NVD data for {year}"

    @pytest.mark.skipif(not LONG_TESTS(), reason="Skipping long tests")
    def test_import_export_json(self):
        main(["cve-bin-tool", "-u", "never", "--export", self.nvd.cachedir])
        cve_entries_check = "SELECT data_source, COUNT(*) as number FROM cve_severity GROUP BY data_source ORDER BY number DESC"
        cursor = self.cvedb.db_open_and_get_cursor()
        cursor.execute(cve_entries_check)
        cve_entries_before = 0
        rows = cursor.fetchall()
        for row in rows:
            entries = row[1]
            cve_entries_before += entries
        self.cvedb.db_close()
        self.cvedb.db_to_json(self.exported_data, "", "")
        self.cvedb.json_to_db_wrapper(
            path=self.exported_data,
            pubkey="",
            ignore_signature=False,
            log_signature_error=False,
        )
        cursor = self.cvedb.db_open_and_get_cursor()
        cursor.execute(cve_entries_check)
        cve_entries_after = 0
        rows = cursor.fetchall()
        for row in rows:
            entries = row[1]
            cve_entries_after += entries
        self.cvedb.db_close()

        assert cve_entries_before == cve_entries_after

    def test_new_database_schema(self):
        # Check if the new schema is created in the database
        self.cvedb.init_database()
        cursor = self.cvedb.db_open_and_get_cursor()

        tables_to_check = ["cve_metrics", "metrics"]
        required_columns = {
            "cve_metrics": ["cve_number", "metric_id", "metric_score", "metric_field"],
            "metrics": ["metrics_id", "metrics_name"],
        }

        for table in tables_to_check:
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
            )
            result = cursor.fetchone()
            assert result is not None  # Assert that the table exists

            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            column_names = [column[1] for column in columns]
            assert all(column in column_names for column in required_columns[table])

        self.cvedb.db_close()
