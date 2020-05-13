#!/usr/bin/python
""" Validates the NIST data feed
1. Against their schema.
This uses the schemas mentioned here: https://nvd.nist.gov/vuln/Data-Feeds/JSON-feed-changelog
2. Against the provided metadata, including the sha256sum
"""
import hashlib
import json
import gzip
import os
import unittest
import datetime
from zipfile import ZipFile
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from test.utils import LONG_TESTS
from cve_bin_tool.cvedb import DISK_LOCATION_DEFAULT

# Try python3 dependency, fall back if not available
try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

NVD_SCHEMA = "https://scap.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema"

# NVD feeds from "https://nvd.nist.gov/vuln/data-feeds#JSON_FEED" but stored locally
NVD_FILE_TEMPLATE = "nvdcve-1.1-{}.json.gz"


class TestJSON(unittest.TestCase):
    @unittest.skipUnless(LONG_TESTS() > 0, "Skipping long tests")
    def test_json_validation(self):
        """ Validate latest nvd json file against their published schema """
        # Download the schema
        schema = json.loads(urlopen(NVD_SCHEMA).read().decode("utf-8"))
        print("Loaded schema")

        # NVD database started in 2002, so range then to now.
        years = list(range(2002, datetime.datetime.now().year + 1))
        # Open the latest nvd file on disk
        for year in years:
            with gzip.open(
                os.path.join(DISK_LOCATION_DEFAULT, f"nvdcve-1.1-{year}.json.gz"), "rb",
            ) as json_file:
                nvd_json = json.loads(json_file.read())
                print(f"Loaded json for year {year}: nvdcve-1.1-{year}.json.gz")

                # Validate -- will raise a ValidationError if not valid
                try:
                    validate(nvd_json, schema)
                    print("Validation complete")
                except ValidationError as ve:
                    print(ve)
                    self.fail("Validation error occured")
