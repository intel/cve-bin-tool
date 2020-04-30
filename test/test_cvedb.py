import os
import shutil
import unittest
import tempfile
import datetime

from cve_bin_tool.cvedb import CVEDB, getmeta, cache_update


class TestCVEDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cvedb = CVEDB(cachedir=tempfile.mkdtemp(prefix="cvedb-"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.cvedb.cachedir)

    def test_00_getmeta(self):
        _jsonurl, meta = getmeta(
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
        )
        self.assertIn("sha256", meta)

    def test_01_nist_scrape(self):
        jsonshas = self.cvedb.nist_scrape(self.cvedb.feed)
        self.assertIn(
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz", jsonshas
        )

    def test_02_cache_update(self):
        jsonurl, meta = getmeta(
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.meta"
        )
        self.assertIn("sha256", meta)
        cache_update(self.cvedb.cachedir, jsonurl, meta["sha256"])

    def test_03_refresh(self):
        self.cvedb.refresh()
        years = self.cvedb.years()
        for year in range(2002, datetime.datetime.now().year):
            self.assertIn(year, years, f"Missing NVD data for {year}")

    def test_04_verify_false(self):
        self.cvedb.verify = False
        with self.cvedb:
            self.assertTrue(
                os.path.isfile(
                    os.path.join(self.cvedb.cachedir, "nvdcve-1.1-2015.json.gz")
                )
            )
