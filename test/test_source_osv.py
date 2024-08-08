# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


import io
import shutil
import tempfile
import zipfile
from pathlib import Path
from test.utils import EXTERNAL_SYSTEM

import aiohttp
import pytest

from cve_bin_tool.data_sources import osv_source
from cve_bin_tool.util import make_http_requests


class TestSourceOSV:
    @classmethod
    def setup_class(cls):
        cls.osv = osv_source.OSV_Source()
        cls.osv.cachedir = tempfile.mkdtemp(prefix="cvedb-")
        cls.osv.osv_path = str(Path(cls.osv.cachedir) / "osv")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.osv.cachedir)

    osv_url = "https://osv-vulnerabilities.storage.googleapis.com/"
    ecosystems_url = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt"

    zip_namelist = [
        "GSD-2021-1000000.json",
        "GSD-2021-1000001.json",
        "GSD-2021-1000002.json",
        "GSD-2021-1000003.json",
        "GSD-2021-1000004.json",
        "GSD-2021-1000005.json",
        "GSD-2021-1000006.json",
        "GSD-2021-1000007.json",
        "GSD-2021-1000008.json",
        "GSD-2021-1000009.json",
        "GSD-2021-1000010.json",
        "GSD-2021-1000040.json",
        "GSD-2021-1000051.json",
        "GSD-2021-1000188.json",
        "GSD-2021-1000189.json",
    ]

    cve_file_data = {
        f"{osv_url}Debian:6.0/DLA-47-1.json": {
            "id": "DLA-47-1",
            "summary": "lua5.1 - security update",
            "details": "\nFix stack overflow in vararg functions.\n\n\nFor Debian 6 Squeeze, these issues have been fixed in lua5.1 version 5.1.4-5+deb6u1\n\n\n",
            "aliases": ["CVE-2014-5461"],
            "modified": "2022-07-21T05:54:26.524614Z",
            "published": "2014-09-05T00:00:00Z",
            "references": [
                {
                    "type": "ADVISORY",
                    "url": "https://www.debian.org/lts/security/2014/dla-47",
                }
            ],
            "affected": [
                {
                    "package": {"name": "lua5.1", "ecosystem": "Debian:6.0"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "5.1.4-5+deb6u1"},
                            ],
                        }
                    ],
                    "versions": ["5.1.4-5"],
                    "database_specific": {
                        "source": "https://storage.googleapis.com/debian-osv/dtsa-osv/DLA-47-1.json"
                    },
                }
            ],
            "schema_version": "1.2.0",
        },
        f"{osv_url}PyPI/PYSEC-2018-103.json": {
            "id": "PYSEC-2018-103",
            "details": "ymlref allows code injection.",
            "aliases": ["CVE-2018-20133", "GHSA-8r8j-xvfj-36f9"],
            "modified": "2021-09-26T23:33:39.795406Z",
            "published": "2018-12-17T19:29:00Z",
            "references": [
                {
                    "type": "REPORT",
                    "url": "https://github.com/dexter2206/ymlref/issues/2",
                },
                {
                    "type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-8r8j-xvfj-36f9",
                },
            ],
            "affected": [
                {
                    "package": {
                        "name": "ymlref",
                        "ecosystem": "PyPI",
                        "purl": "pkg:pypi/ymlref",
                    },
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                    "versions": ["0.1.0", "0.1.1"],
                    "database_specific": {
                        "source": "https://github.com/pypa/advisory-database/blob/main/vulns/ymlref/PYSEC-2018-103.yaml"
                    },
                }
            ],
            "schema_version": "1.2.0",
        },
    }

    format_data = {
        "PYSEC-2018-103": {
            "severity_data": {
                "ID": "PYSEC-2018-103",
                "severity": "unknown",
                "description": "unknown",
                "score": "unknown",
                "CVSS_version": "unknown",
                "CVSS_vector": "unknown",
                "last_modified": "2021-09-26T23:33:39.795406Z",
            },
            "affected_data": [
                {
                    "cve_id": "PYSEC-2018-103",
                    "vendor": "unknown",
                    "product": "ymlref",
                    "version": "*",
                    "versionStartIncluding": "0.1.0",
                    "versionStartExcluding": "",
                    "versionEndIncluding": "0.1.1",
                    "versionEndExcluding": "",
                }
            ],
        },
        "DLA-47-1": {
            "severity_data": {
                "ID": "DLA-47-1",
                "severity": "unknown",
                "description": "lua5.1 - security update",
                "score": "unknown",
                "CVSS_version": "unknown",
                "CVSS_vector": "unknown",
                "last_modified": "2022-07-21T05:54:26.524614Z",
            },
            "affected_data": [
                {
                    "cve_id": "DLA-47-1",
                    "vendor": "unknown",
                    "product": "lua5.1",
                    "version": "*",
                    "versionStartIncluding": "5.1.4-5",
                    "versionStartExcluding": "",
                    "versionEndIncluding": "5.1.4-5",
                    "versionEndExcluding": "",
                }
            ],
        },
    }

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    async def test_update_ecosystems(self):
        await self.osv.update_ecosystems()

        ecosystems_txt = make_http_requests(
            "text", url=self.ecosystems_url, timeout=300
        ).strip("\n")
        expected_ecosystems = set(ecosystems_txt.split("\n"))

        # Because ecosystems.txt does not contain the complete list, this must be
        # manually fixed up.
        expected_ecosystems.add("DWF")
        expected_ecosystems.add("JavaScript")

        # Assert that there are no missing ecosystems
        assert all(x in self.osv.ecosystems for x in expected_ecosystems)
        # Assert that there are no extra ecosystems
        assert all(x in expected_ecosystems for x in self.osv.ecosystems)

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    @pytest.mark.parametrize("ecosystem_url", [url for url in cve_file_data])
    async def test_get_ecosystem_00(self, ecosystem_url):
        connector = aiohttp.TCPConnector(limit_per_host=19)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=True
        ) as session:
            content = await self.osv.get_ecosystem(ecosystem_url, session)

        cve_data = self.cve_file_data[ecosystem_url]

        assert content["id"] == cve_data["id"]
        assert content["published"] == cve_data["published"]

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    async def test_get_ecosystem_01(self):
        eco_url = f"{self.osv_url}DWF/all.zip"

        connector = aiohttp.TCPConnector(limit_per_host=19)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=True
        ) as session:
            content = await self.osv.get_ecosystem(eco_url, session, mode="bytes")

        z = zipfile.ZipFile(io.BytesIO(content))

        # Shouldn't be any files as DWF is no longer a valid ecosystems
        assert len(z.namelist()) == 0

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    async def test_fetch_cves(self):
        self.osv.ecosystems = ["PyPI"]

        await self.osv.fetch_cves()

        p = Path(self.osv.osv_path).glob("**/*")
        files = [x.name for x in p if x.is_file()]

        # Check some files have been processed
        assert len(files) > 0
        # Check that some Python files have been extracted
        pysecfiles = [x for x in files if x.startswith("PYSEC-")]
        assert len(pysecfiles) > 0

    @pytest.mark.parametrize("cve_entries", [[x] for _, x in cve_file_data.items()])
    def test_format_data(self, cve_entries):
        severity_data, affected_data = self.osv.format_data(cve_entries)

        severity_data = severity_data[0]

        assert severity_data == self.format_data[severity_data["ID"]]["severity_data"]
        assert affected_data == self.format_data[severity_data["ID"]]["affected_data"]
