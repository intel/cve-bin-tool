# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" Validates the NIST data feed
1. Against their schema.
This uses the schemas mentioned here: https://nvd.nist.gov/vuln/Data-Feeds/JSON-feed-changelog
2. Against the provided metadata, including the sha256sum
"""
import datetime
import gzip
import json
from pathlib import Path
from test.utils import EXTERNAL_SYSTEM, LONG_TESTS

import pytest
from jsonschema import validate
from jsonschema.exceptions import ValidationError

from cve_bin_tool.cvedb import DISK_LOCATION_DEFAULT
from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import make_http_requests

NVD_SCHEMA = "https://scap.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema"
# NVD feeds from "https://nvd.nist.gov/vuln/data-feeds#JSON_FEED" but stored locally


@pytest.mark.skipif(
    not EXTERNAL_SYSTEM(), reason="Skipping tests to reduce network calls"
)
class TestJSON:
    # Download the schema
    # timeout 300s/5min, may need to be changed
    SCHEMA = make_http_requests("json", url=NVD_SCHEMA, timeout=300)
    LOGGER.info("Schema loaded successfully")

    @pytest.mark.skipif(not LONG_TESTS(), reason="Skipping long tests")
    @pytest.mark.parametrize(
        "year", list(range(2002, datetime.datetime.now().year + 1))
    )
    # NVD database started in 2002, so range then to now.
    @pytest.mark.xfail(reason="NVD data is sometimes imperfect", run=True)
    def test_json_validation(self, year):
        """Validate latest nvd json file against their published schema"""
        # Open the latest nvd file on disk
        with gzip.open(
            Path(DISK_LOCATION_DEFAULT) / f"nvdcve-1.1-{year}.json.gz",
            "rb",
        ) as json_file:
            nvd_json = json.loads(json_file.read())
            LOGGER.info(f"Loaded json for year {year}: nvdcve-1.1-{year}.json.gz")

            # Validate -- will raise a ValidationError if not valid
            try:
                validate(nvd_json, self.SCHEMA)
                LOGGER.info("Validation complete")
            except ValidationError as ve:
                LOGGER.error(ve)
                pytest.fail("Validation error occurred")
