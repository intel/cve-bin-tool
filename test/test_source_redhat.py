# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
from pathlib import Path

import pytest

from cve_bin_tool.data_sources import redhat_source


class TestSourceRedHat:
    @classmethod
    def setup_class(cls):
        cls.redhat = redhat_source.REDHAT_Source()
        cls.redhat.redhat_path = Path(__file__).parent.resolve() / "redhat"

    @pytest.mark.asyncio
    async def test_update_cve_entries(self):
        self.redhat.time_of_last_update = None
        assert len(self.redhat.all_cve_entries) == 0
        # Should get all files
        await self.redhat.update_cve_entries()
        # Expecting 3 files
        assert len(self.redhat.all_cve_entries) == 3
        # Now check contents match the data files
        for c in self.redhat.all_cve_entries:
            assert c["CVE"].startswith("CVE-2022-")
            assert c["severity"] in ["important", "moderate", "low"]
            assert c["cvss3_score"] is not None

    @pytest.mark.asyncio
    async def test_incremental_update_cve_entries(self):
        # Time is now
        self.redhat.time_of_last_update = datetime.datetime.today()
        # Should be no new files found
        await self.redhat.update_cve_entries()
        assert len(self.redhat.all_cve_entries) == 0

    @pytest.mark.asyncio
    async def test_format_data(self):
        self.redhat.time_of_last_update = None
        # Should get all files
        await self.redhat.update_cve_entries()
        # Now process data
        severity_data, affected_data = self.redhat.format_data(
            self.redhat.all_cve_entries
        )

        # Check that some data exists
        assert len(severity_data) > 0
        assert len(affected_data) > 0

        # Check severity mapping
        for d in severity_data:
            # Verify that Redhat severities have been mapped to correct severities
            assert d["severity"] not in ["important", "moderate", "low"]
            assert d["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

        # Check vendor and version
        for d in affected_data:
            # All products are assumed to be redhat
            assert d["vendor"] == "redhat"
            assert d["version"] is not None
