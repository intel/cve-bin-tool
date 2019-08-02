#!/usr/bin/python
""" Validates the NIST data feed
1. Against their schema.
This uses the schemas mentioned here: https://nvd.nist.gov/vuln/Data-Feeds/JSON-feed-changelog
2. Against the provided metadata, including the sha256sum
"""
import hashlib
import json
import os
import unittest
from zipfile import ZipFile
from jsonschema import validate

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

NVD_SCHEMA = "https://scap.nist.gov/schema/nvd/feed/1.0/nvd_cve_feed_json_1.0.schema"
NVD_2019_META = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2019.meta"


# NVD feeds from "https://nvd.nist.gov/vuln/data-feeds#JSON_FEED" but stored locally
DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "cve-bin-tool")
LATEST_NVD = os.path.join(DISK_LOCATION_DEFAULT, "nvd", "nvdcve-1.0-2019.json.zip")
NVD_FILE = "nvdcve-1.0-2019.json"


class TestJSON(unittest.TestCase):
    def test_json_validation(self):
        """ Validate latest nvd json file against their published schema """
        # Download the schema
        schema = json.loads(urlopen(NVD_SCHEMA).read().decode("utf-8"))
        print("Loaded schema")

        # Open the latest nvd zipfile on disk
        with ZipFile(LATEST_NVD, "r") as json_zip:
            with json_zip.open(NVD_FILE) as json_file:
                nvd_json = json.loads(json_file.read().decode("utf-8"))
                print("Loaded json")

                # Validate -- will raise a ValidationError if not valid
                try:
                    validate(nvd_json, schema)
                    print("Validation complete")
                except ValidationError as ve:
                    print(ve)
                    self.fail("Validation error occured")

    @unittest.skip("Diagnostic; only useful against fresh nvdfile")
    def test_meta(self):
        """ Validate latest nvd json file against meta including sha256 sum """
        meta = urlopen(NVD_2019_META).read().decode("utf-8")
        # Meta lines are lastModifiedDate, size, zipSize, gzSize, sha256
        lines = meta.splitlines()

        # check the zip size
        zipsize = lines[2].split(":")[1]
        print("Expected size: {}".format(zipsize))
        print("Actual size: {}".format(os.stat(LATEST_NVD).st_size))
        self.assertEqual(int(zipsize), os.stat(LATEST_NVD).st_size)

        sha256 = lines[4].split(":")[1].lower()
        print("Expected sha256 hash: {}".format(sha256))
        with ZipFile(LATEST_NVD, "r") as json_zip:
            with json_zip.open(NVD_FILE) as json_file:
                json_sha256 = hashlib.sha256(json_file.read()).hexdigest()
                print("Actual sha256 hash: {}".format(json_sha256))
                self.assertEqual(sha256, json_sha256)
