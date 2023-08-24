# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from ast import literal_eval
from collections import defaultdict
from pathlib import Path

import pytest

from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.input_engine import (
    InputEngine,
    InvalidCsvError,
    InvalidJsonError,
    MissingFieldsError,
    Remarks,
)
from cve_bin_tool.util import ProductInfo


class TestInputEngine:
    TMP_DIR = Path(__file__).parent.resolve()
    CSV_PATH = TMP_DIR / "csv"
    JSON_PATH = TMP_DIR / "json"
    VEX_PATH = TMP_DIR / "vex"
    PARSED_TRIAGE_DATA = {
        ProductInfo("haxx", "curl", "7.59.0"): {
            "default": {"comments": "", "remarks": Remarks.NewFound, "severity": ""},
            "paths": {""},
        },
        ProductInfo("haxx", "libcurl", "7.59.0"): {
            "default": {"comments": "", "remarks": Remarks.Unexplored, "severity": ""},
            "paths": {""},
        },
        ProductInfo("libjpeg-turbo", "libjpeg-turbo", "2.0.1"): {
            "CVE-2018-19664": {
                "comments": "High priority need to resolve fast",
                "remarks": Remarks.Confirmed,
                "severity": "CRITICAL",
            },
            "default": {
                "comments": "Need to mitigate cves of this product",
                "remarks": Remarks.Unexplored,
                "severity": "HIGH",
            },
            "paths": {""},
        },
        ProductInfo("mit", "kerberos_5", "1.15.1"): {
            "default": {"comments": "", "remarks": Remarks.Confirmed, "severity": ""},
            "paths": {""},
        },
        ProductInfo("ssh", "ssh2", "2.0"): {
            "default": {"comments": "", "remarks": Remarks.Mitigated, "severity": ""},
            "paths": {""},
        },
        ProductInfo("sun", "sunos", "5.4"): {
            "default": {"comments": "", "remarks": Remarks.Mitigated, "severity": ""},
            "paths": {""},
        },
    }
    VEX_TRIAGE_DATA = {
        ProductInfo("d.r.commander", "libjpeg-turbo", "2.0.1"): {
            "CVE-2018-19664": {
                "comments": "High priority need to resolve fast",
                "remarks": Remarks.Confirmed,
                "severity": "CRITICAL",
            },
            "paths": {},
        },
        ProductInfo("gnu", "glibc", "2.33"): {
            "CVE-2021-1234": {
                "comments": "",
                "remarks": Remarks.Unexplored,
                "severity": "HIGH",
            },
            "paths": {},
        },
    }
    # cyclonedx currently doesn't have vendors
    VEX_TRIAGE_DATA_CYCLONEDX = {
        ProductInfo("UNKNOWN", "libjpeg-turbo", "2.0.1"): {
            "CVE-2018-19664": {
                "comments": "High priority need to resolve fast",
                "remarks": Remarks.Confirmed,
                "severity": "CRITICAL",
            },
            "paths": {},
        },
        ProductInfo("UNKNOWN", "glibc", "2.33"): {
            "CVE-2021-1234": {
                "comments": "",
                "remarks": Remarks.Unexplored,
                "severity": "HIGH",
            },
            "paths": {},
        },
    }
    MISSING_FIELD_REGEX = re.compile(
        r"({[' ,](([a-z])+[' ,]{1,4})+}) are required fields"
    )

    @pytest.mark.parametrize(
        "filepath",
        (
            str(CSV_PATH / "nonexistent.csv"),
            str(JSON_PATH / "nonexistent.json"),
        ),
    )
    def test_nonexistent_file(self, filepath):
        input_engine = InputEngine(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(FileNotFoundError):
            input_engine.parse_input()

    @pytest.mark.parametrize(
        "filepath, exception",
        (
            (str(CSV_PATH / "bad.csv"), InvalidCsvError),
            (str(JSON_PATH / "bad.json"), InvalidJsonError),
        ),
    )
    def test_invalid_file(self, filepath, exception):
        input_engine = InputEngine(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(exception):
            input_engine.parse_input()

    @pytest.mark.parametrize(
        "filepath, missing_fields",
        (
            (str(CSV_PATH / "bad_product.csv"), {"product"}),
            (
                str(CSV_PATH / "bad_heading.csv"),
                {"vendor", "product", "version"},
            ),
            (
                str(JSON_PATH / "bad_heading.json"),
                {"vendor", "product", "version"},
            ),
        ),
    )
    def test_missing_fields(self, filepath, missing_fields):
        input_engine = InputEngine(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(MissingFieldsError) as exc:
            input_engine.parse_input()

        match = self.MISSING_FIELD_REGEX.search(exc.value.args[0])
        raised_fields = match.group(1)

        assert missing_fields - literal_eval(raised_fields) == set()

    @pytest.mark.parametrize(
        "filepath, parsed_data",
        (
            (str(CSV_PATH / "test_triage.csv"), PARSED_TRIAGE_DATA),
            (str(JSON_PATH / "test_triage.json"), PARSED_TRIAGE_DATA),
        ),
    )
    def test_valid_file(self, filepath, parsed_data):
        input_engine = InputEngine(filepath, error_mode=ErrorMode.FullTrace)
        assert dict(input_engine.parse_input()) == parsed_data

    @pytest.mark.parametrize(
        "filepath, parsed_data",
        (
            (str(VEX_PATH / "test_triage.vex"), VEX_TRIAGE_DATA),
            (str(VEX_PATH / "test_triage_cyclonedx.vex"), VEX_TRIAGE_DATA_CYCLONEDX),
            (str(VEX_PATH / "bad.vex"), defaultdict(dict)),
        ),
    )
    def test_vex_file(self, filepath, parsed_data):
        input_engine = InputEngine(filepath, error_mode=ErrorMode.FullTrace)
        assert dict(input_engine.parse_input()) == parsed_data

    @pytest.mark.parametrize(
        "product, product_result",
        (
            ("gcc", True),
            ("not_a_bad%product", True),
            ("12!", False),
            ("!Superproduct", False),
        ),
    )
    def test_valid_product_name(self, product, product_result):
        input_engine = InputEngine("temp.txt", error_mode=ErrorMode.FullTrace)
        assert input_engine.validate_product(product) == product_result
