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

from cve_bin_tool.data_sources import gad_source


class TestSourceGAD:
    @classmethod
    def setup_class(cls):
        cls.gad = gad_source.GAD_Source()
        cls.gad.cachedir = tempfile.mkdtemp(prefix="cvedb-")
        cls.gad.gad_path = str(Path(cls.gad.cachedir) / "gad")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.gad.cachedir)

    slugs = ["conan", "gem", "go", "maven", "npm", "nuget", "packagist", "pypi"]

    parsed_range = {
        "<2.17.3": [
            {
                "version": "*",
                "versionEndExcluding": "2.17.3",
                "versionEndIncluding": "",
                "versionStartExcluding": "",
                "versionStartIncluding": "",
            }
        ],
        "<1.0.2||=1.1.0||=3.0.0": [
            {
                "version": "*",
                "versionEndExcluding": "1.0.2",
                "versionEndIncluding": "",
                "versionStartExcluding": "",
                "versionStartIncluding": "",
            },
            {
                "version": "1.1.0",
                "versionEndExcluding": "",
                "versionEndIncluding": "",
                "versionStartExcluding": "",
                "versionStartIncluding": "",
            },
            {
                "version": "3.0.0",
                "versionEndExcluding": "",
                "versionEndIncluding": "",
                "versionStartExcluding": "",
                "versionStartIncluding": "",
            },
        ],
        "[4.4.0],(,4.2.0)": [
            {
                "version": "4.4.0",
                "versionEndExcluding": "",
                "versionEndIncluding": "",
                "versionStartExcluding": "",
                "versionStartIncluding": "",
            },
            {
                "version": "*",
                "versionEndExcluding": "4.2.0",
                "versionEndIncluding": "",
                "versionStartExcluding": "",
                "versionStartIncluding": "",
            },
        ],
        "(,1.0],[1.2,)": [
            {
                "version": "*",
                "versionEndExcluding": "",
                "versionEndIncluding": "1.0",
                "versionStartExcluding": "",
                "versionStartIncluding": "",
            },
            {
                "version": "*",
                "versionEndExcluding": "",
                "versionEndIncluding": "",
                "versionStartExcluding": "",
                "versionStartIncluding": "1.2",
            },
        ],
    }

    cve_file_data = {
        "CVE-2020-15365": {
            "identifier": "CVE-2020-15365",
            "package_slug": "conan/libraw",
            "title": "Out-of-bounds Write",
            "description": "LibRaw before has an out-of-bounds write in `parse_exif()` in `metadata\\exif_gps.cpp` via an unrecognized `AtomName` and a zero value of `tiff_nifds`.",
            "date": "2020-07-06",
            "pubdate": "2020-06-28",
            "affected_range": "<0.20",
            "fixed_versions": [],
            "affected_versions": "All versions before 0.20",
            "not_impacted": "",
            "solution": "Unfortunately, there is no solution available yet.",
            "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2020-15365"],
            "cvss_v2": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
            "cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
            "uuid": "731761de-31d8-40d3-97b5-8b48338a36f9",
            "cwe_ids": ["CWE-1035", "CWE-787", "CWE-937"],
            "identifiers": ["CVE-2020-15365"],
        },
        "CVE-2020-24870": {
            "identifier": "CVE-2020-24870",
            "package_slug": "conan/libraw",
            "title": "Out-of-bounds Write",
            "description": "Libraw has a stack buffer overflow via LibRaw::identify_process_dng_fields in identify.cpp.",
            "date": "2021-06-10",
            "pubdate": "2021-06-02",
            "affected_range": "<0.20.1",
            "fixed_versions": ["0.20.2"],
            "affected_versions": "All versions before 0.20.1",
            "not_impacted": "All versions starting from 0.20.1",
            "solution": "Upgrade to version 0.20.2 or above.",
            "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2020-24870"],
            "cvss_v2": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
            "cvss_v3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "uuid": "30c73a05-ccaf-4cd8-9ea1-d0006b93f5e7",
            "cwe_ids": ["CWE-1035", "CWE-787", "CWE-937"],
            "identifiers": ["CVE-2020-24870"],
        },
    }

    severity_data = {
        "CVE-2020-15365": {
            "ID": "CVE-2020-15365",
            "severity": "Medium",
            "description": "LibRaw before has an out-of-bounds write in `parse_exif()` in `metadata\\exif_gps.cpp` via an unrecognized `AtomName` and a zero value of `tiff_nifds`.",
            "score": 6.5,
            "CVSS_version": "3",
            "CVSS_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
            "last_modified": "2020-07-06",
        },
        "CVE-2020-24870": {
            "ID": "CVE-2020-24870",
            "severity": "High",
            "description": "Libraw has a stack buffer overflow via LibRaw::identify_process_dng_fields in identify.cpp.",
            "score": 8.8,
            "CVSS_version": "3",
            "CVSS_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "last_modified": "2021-06-10",
        },
    }

    affected_data = {
        "CVE-2020-15365": [
            {
                "cve_id": "CVE-2020-15365",
                "vendor": "unknown",
                "product": "libraw",
                "version": "*",
                "versionStartIncluding": "",
                "versionStartExcluding": "",
                "versionEndIncluding": "",
                "versionEndExcluding": "0.20",
            }
        ],
        "CVE-2020-24870": [
            {
                "cve_id": "CVE-2020-24870",
                "vendor": "unknown",
                "product": "libraw",
                "version": "*",
                "versionStartIncluding": "",
                "versionStartExcluding": "",
                "versionEndIncluding": "",
                "versionEndExcluding": "0.20.1",
            }
        ],
    }

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    async def test_update_slugs(self):
        connector = aiohttp.TCPConnector(limit_per_host=19)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=True
        ) as session:
            await self.gad.update_slugs(session)

        assert all(x in self.gad.slugs for x in self.slugs)

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    async def test_get_slug_00(self):
        slug_url = f"{self.gad.gad_url}?path=conan/cairo"

        connector = aiohttp.TCPConnector(limit_per_host=19)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=True
        ) as session:
            content = await self.gad.get_slug(slug_url, session, mode="bytes")

        z = zipfile.ZipFile(io.BytesIO(content))

        assert ("CVE-2020-35492.yml" in x for x in z.namelist())

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    async def test_get_slug_01(self):
        slug_url = f"{self.gad.gad_compare_url}?from=aa3c4bf5605855aff8c26363a24bff6da45d4812&to=a0979afc34fc6692ae8e48b3d7604e27062add62"

        connector = aiohttp.TCPConnector(limit_per_host=19)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=True
        ) as session:
            content = await self.gad.get_slug(slug_url, session)

        assert content["commit"]["short_id"] == "a0979afc"

    @pytest.mark.parametrize("range_string", [x for x in parsed_range])
    def test_parse_range_string(self, range_string):
        parsed_data = self.gad.parse_range_string(range_string)

        assert parsed_data == self.parsed_range[range_string]

    @pytest.mark.parametrize("cve_entries", [[x] for _, x in cve_file_data.items()])
    def test_format_data(self, cve_entries):
        severity_data, affected_data = self.gad.format_data(cve_entries)

        severity_data = severity_data[0]

        assert severity_data == self.severity_data[cve_entries[0]["identifier"]]
        assert affected_data == self.affected_data[cve_entries[0]["identifier"]]
