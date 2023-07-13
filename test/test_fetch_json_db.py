# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool Fetch JSON from mirror tests
"""

import asyncio
import json
import shutil
import tempfile
from pathlib import Path

import pytest

from cve_bin_tool.fetch_json_db import Fetch_JSON_DB


class Test_Fetch_JSON:
    """Tests the CVE Bin Tool Fetch JSON from mirror feature"""

    DUMMY_METADATA = {
        "timestamp": 1679491799.606112,
        "db": {
            "cve_severity": [
                "2023",
            ],
            "cve_range": [
                "2023",
            ],
            "cve_exploited": [
                "2023",
            ],
        },
    }

    DUMMY_DB = {
        "cve_severity": {
            "2023": {
                "cve_number": "CVE-2023-0028",
                "severity": "MEDIUM",
                "description": "Cross-site Scripting (XSS) - Stored in GitHub repository linagora/twake prior to 2023.Q1.1200+.",
                "score": 6.1,
                "cvss_version": 3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "data_source": "NVD",
                "last_modified": "2023-01-06T21:36Z",
            }
        },
        "cve_range": {
            "2023": {
                "cve_number": "CVE-2023-0028",
                "vendor": "linagora",
                "product": "twake",
                "version": "*",
                "versionStartIncluding": "",
                "versionStartExcluding": "",
                "versionEndIncluding": "2022.q4.1120",
                "versionEndExcluding": "",
                "data_source": "NVD",
            }
        },
        "cve_exploited": {
            "2023": {
                "cve_number": "CVE-2023-21674",
                "product": "Windows",
                "description": "Microsoft Windows Advanced Local Procedure Call (ALPC) contains an unspecified vulnerability that allows for privilege escalation.",
            }
        },
    }

    @classmethod
    def setup_class(cls):
        cls.tempdir = Path(tempfile.mkdtemp(prefix="cve-bin-tool-cache-"))
        cls.mirror_client = Fetch_JSON_DB(
            mirror="https://raw.githubusercontent.com/sec-data/mirror-sandbox/main/exported_data",
            cache_dir=cls.tempdir,
            pubkey="",
            ignore_signature=True,
            log_signature_error=False,
        )
        cls.mock_response = MockResponse(cls.DUMMY_METADATA, cls.DUMMY_DB)

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir)

    @pytest.mark.asyncio
    async def test_fetch_json_from_mirror(self, mocker):
        mocker.patch(
            "aiohttp.ClientSession.get",
            side_effect=self.mock_response.side_effect,
        )
        await self.mirror_client.handle_download()

        # verify metadata
        with open(self.tempdir / "json_data" / "metadata.json") as metadata:
            assert json.loads(metadata.read()) == self.DUMMY_METADATA

        # verify downloaded json files
        with open(
            self.tempdir / "json_data" / "cve_severity" / "2023.json"
        ) as cve_severity:
            assert (
                json.loads(cve_severity.read()) == self.DUMMY_DB["cve_severity"]["2023"]
            )

        with open(self.tempdir / "json_data" / "cve_range" / "2023.json") as cve_range:
            assert json.loads(cve_range.read()) == self.DUMMY_DB["cve_range"]["2023"]

        with open(
            self.tempdir / "json_data" / "cve_exploited" / "2023.json"
        ) as cve_exploited:
            assert (
                json.loads(cve_exploited.read())
                == self.DUMMY_DB["cve_exploited"]["2023"]
            )


class MockResponse:
    def __init__(self, metadata, db):
        self.url = ""
        self.metadata = metadata
        self.db = db
        self.status = 200

    def side_effect(self, url):
        mock_response = MockResponse(self.metadata, self.db)
        mock_response.url = url
        async_mock_response = asyncio.Future()
        async_mock_response.set_result(mock_response)
        return async_mock_response

    def raise_for_status(self):
        return True

    async def read(self):
        if self.url.endswith("metadata.json"):
            return json.dumps(self.metadata).encode("utf-8")
        else:
            url = self.url.split("/")
            directory = url[len(url) - 2]
            file = url[len(url) - 1].replace(".json", "")
            return json.dumps(self.db[directory][file]).encode("utf-8")
