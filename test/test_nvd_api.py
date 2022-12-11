# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import shutil
import tempfile
from datetime import datetime, timedelta
from test.utils import EXTERNAL_SYSTEM

import pytest

from cve_bin_tool.cvedb import CVEDB
from cve_bin_tool.data_sources import nvd_source
from cve_bin_tool.nvd_api import NVD_API


class TestNVD_API:
    @classmethod
    def setup_class(cls):
        cls.outdir = tempfile.mkdtemp(prefix="cvedb-api-")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.outdir)

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM() or not os.getenv("nvd_api_key"),
        reason="NVD tests run only when EXTERNAL_SYSTEM=1",
    )
    async def test_get_nvd_params(self):
        """Test NVD for a future date. It should be empty"""
        nvd_api = NVD_API(api_key=os.getenv("nvd_api_key") or "")
        await nvd_api.get_nvd_params(
            time_of_last_update=(datetime.now() + timedelta(days=2))
        )
        await nvd_api.get()
        assert nvd_api.total_results == 0 and nvd_api.all_cve_entries == []

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM() or not os.getenv("nvd_api_key"),
        reason="NVD tests run only when EXTERNAL_SYSTEM=1",
    )
    async def test_total_results_count(self):
        """Total results should be greater than or equal to the current fetched cves"""
        nvd_api = NVD_API(api_key=os.getenv("nvd_api_key") or "")
        await nvd_api.get_nvd_params(
            time_of_last_update=datetime.now() - timedelta(days=2)
        )
        await nvd_api.get()
        assert len(nvd_api.all_cve_entries) >= nvd_api.total_results

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM() or not os.getenv("nvd_api_key"),
        reason="NVD tests run only when EXTERNAL_SYSTEM=1",
    )
    async def test_nvd_incremental_update(self):
        """Test to check whether we are able to fetch and save the nvd entries using time_of_last_update"""
        nvd_api = NVD_API(
            incremental_update=True, api_key=os.getenv("nvd_api_key") or ""
        )
        await nvd_api.get_nvd_params(
            time_of_last_update=datetime.now() - timedelta(days=4)
        )
        await nvd_api.get()
        source_nvd = nvd_source.NVD_Source()
        cvedb = CVEDB(cachedir=self.outdir)
        cvedb.data = [(source_nvd.format_data(nvd_api.all_cve_entries), "NVD")]
        cvedb.init_database()
        cvedb.populate_db()
        cvedb.check_cve_entries()
        assert cvedb.cve_count == nvd_api.total_results

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM() or not os.getenv("nvd_api_key"),
        reason="NVD tests run only when EXTERNAL_SYSTEM=1",
    )
    async def test_empty_nvd_result(self):
        """Test to check nvd results non-empty result. Total result should be greater than 0"""
        nvd_api = NVD_API(api_key=os.getenv("nvd_api_key") or "")
        await nvd_api.get_nvd_params()
        assert nvd_api.total_results > 0

    @pytest.mark.asyncio
    @pytest.mark.skip(reason="NVD does not return the Received count")
    async def test_api_cve_count(self):
        """Test to match the totalResults and the total CVE count on NVD"""

        nvd_api = NVD_API(api_key=os.getenv("nvd_api_key") or "")
        await nvd_api.get_nvd_params()
        await nvd_api.load_nvd_request(0)
        cve_count = await nvd_api.nvd_count_metadata(nvd_api.session)

        # Difference between the total and rejected CVE count on NVD should be equal to the total CVE count
        # Received CVE count might be zero
        assert (
            abs(nvd_api.total_results - (cve_count["Total"] - cve_count["Rejected"]))
            <= cve_count["Received"]
        )
