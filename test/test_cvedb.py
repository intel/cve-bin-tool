# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import shutil
import sys
import tempfile
from test.utils import EXTERNAL_SYSTEM

import pytest

from cve_bin_tool import cvedb
from cve_bin_tool.data_sources import nvd_source


class TestCVEDB:
    @classmethod
    def setup_class(cls):
        cls.nvd = nvd_source.NVD_Source(nvd_type="json")
        cachedir = tempfile.mkdtemp(prefix="cvedb-")
        cls.cvedb = cvedb.CVEDB(sources=[cls.nvd], cachedir=cachedir)
        cls.nvd.cachedir = cachedir

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.nvd.cachedir)

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not EXTERNAL_SYSTEM(), reason="Skipping NVD calls due to rate limits"
    )
    @pytest.mark.skipif(
        sys.platform == "win32", reason="Causing failures in CI on windows only"
    )
    async def test_refresh_nvd_json(self):
        await self.cvedb.refresh()
        years = self.nvd.nvd_years()
        for year in range(2002, datetime.datetime.now().year):
            assert year in years, f"Missing NVD data for {year}"
