# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from test.utils import EXTERNAL_SYSTEM

import pytest

from cve_bin_tool.data_sources import purl2cpe_source


class TestSourceOSV:
    @classmethod
    def setup_class(cls):
        cls.purl2cpe = purl2cpe_source.PURL2CPE_Source()
        cls.purl2cpe.cachedir = tempfile.mkdtemp(prefix="cvedb-")
        cls.purl2cpe.purl2cpe_path = str(Path(cls.purl2cpe.cachedir) / "purl2cpe")
        cls.local_path = Path("~").expanduser() / ".cache" / "cve-bin-tool" / "purl2cpe"

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.purl2cpe.cachedir)

    @pytest.mark.asyncio
    @pytest.mark.skipif(not EXTERNAL_SYSTEM(), reason="Needs network connection.")
    async def test_fetch_cves(self):
        await self.purl2cpe.fetch_cves()

    @pytest.fixture(scope="class")
    def db_paths(self):
        return [self.purl2cpe.purl2cpe_path, self.local_path]

    @pytest.mark.parametrize(
        "index, skipif", [(0, not EXTERNAL_SYSTEM()), (1, EXTERNAL_SYSTEM())]
    )
    def test_db_contents(self, index, skipif, request):
        if skipif:
            pytest.skip("Needs network connection.")

        db_paths = request.getfixturevalue("db_paths")
        db_path = db_paths[index]

        p = Path(db_path).glob("**/*")
        file_name = [x.name for x in p if x.is_file()]

        assert file_name == ["purl2cpe.db"]

        file_path = os.path.join(db_path, "purl2cpe.db")
        file_size = os.path.getsize(file_path)

        # Check if the database size is greater than 300 mbs
        assert file_size > 300 * 1024 * 1024

        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        cursor.execute("SELECT purl FROM purl2cpe;")
        result = cursor.fetchall()
        outcome = [r[0] for r in result]
        conn.close()

        expected = [
            "pkg:/sourceforge/openclassify",
            "pkg:1234n/minicms",
            "pkg:13thmonkey/udfclient",
            "pkg:23systems/lightbox-plus-for-wordpress",
            "pkg:2glux/sexypolling",
            "pkg:2pisoftware/cmfive",
            "pkg:Deb/debian/jpeg-xl",
            "pkg:Deb/debian/optipng",
            "pkg:Deb/debian/python-pip",
            "pkg:Deb/ubuntu/apt",
            "pkg:Deb/ubuntu/colord",
            "pkg:Deb/ubuntu/condor",
            "pkg:Deb/ubuntu/firebird",
            "pkg:Deb/ubuntu/libpcap",
            "pkg:Deb/ubuntu/pidgin-otr",
            "pkg:Deb/ubuntu/python-aniso8601",
            "pkg:Deb/ubuntu/xapian-core",
            "pkg:Docker/bitnami/argo-cd",
            "pkg:Docker/logstash",
            "pkg:Gitlab/ubports/libxkbcommon",
        ]

        missing_elements = [pkg for pkg in expected if pkg not in outcome]
        assert not missing_elements, f"Missing elements in database: {missing_elements}"
