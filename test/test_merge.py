# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import re
from pathlib import Path

import pytest

from cve_bin_tool.cve_scanner import CVEScanner
from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.merge import (
    REQUIRED_INTERMEDIATE_METADATA,
    InvalidJsonError,
    MergeReports,
)
from cve_bin_tool.util import ProductInfo, Remarks


class TestMergeReports:
    INTERMEDIATE_PATH = Path(__file__).parent.resolve() / "json"

    MERGED_TRIAGE_DATA = {
        ProductInfo(
            vendor="libjpeg-turbo",
            product="libjpeg-turbo",
            version="2.0.1",
            location="location/to/product",
        ): {
            "CVE-2018-19664": {
                "remarks": Remarks.Confirmed,
                "comments": "High priority need to resolve fast",
                "severity": "CRITICAL",
            },
            "paths": {""},
            "CVE-2018-20330": {
                "remarks": Remarks.Unexplored,
                "comments": "Need to mitigate cves of this product",
                "severity": "HIGH",
            },
            "CVE-2020-17541": {
                "remarks": Remarks.Unexplored,
                "comments": "Need to mitigate cves of this product",
                "severity": "HIGH",
            },
        }
    }

    MISSING_FIELD_REGEX = re.compile(r"({.+}) are required fields")

    @pytest.mark.parametrize(
        "filepaths, exception",
        (([str(INTERMEDIATE_PATH / "bad.json")], InvalidJsonError),),
    )
    def test_invalid_file(self, filepaths, exception):
        merged_cves = MergeReports(
            merge_files=filepaths, error_mode=ErrorMode.FullTrace
        )
        with pytest.raises(exception):
            merged_cves.merge_intermediate()

    @pytest.mark.parametrize(
        "filepaths,missing_fields",
        (
            (
                [str(INTERMEDIATE_PATH / "bad_intermediate.json")],
                {"metadata", "report"},
            ),
            (
                [str(INTERMEDIATE_PATH / "bad_metadata.json")],
                REQUIRED_INTERMEDIATE_METADATA,
            ),
        ),
    )
    def test_missing_fields(self, filepaths, missing_fields, caplog):
        merged_cves = MergeReports(
            merge_files=filepaths, error_mode=ErrorMode.FullTrace
        )
        merged_cves.logger.setLevel(logging.DEBUG)
        merged_cves.merge_intermediate()

        expected_string = str(missing_fields)
        actual_string = caplog.records[-1].getMessage().split("}")[0] + "}"

        expected_set = set(expected_string.strip("{}").split(", "))
        actual_set = set(actual_string.strip("{}").split(", "))

        assert expected_set == actual_set

    @pytest.mark.parametrize(
        "filepaths, merged_data",
        (
            (
                [str(INTERMEDIATE_PATH / "test_intermediate.json")],
                MERGED_TRIAGE_DATA,
            ),
        ),
    )
    def test_valid_merge(self, filepaths, merged_data):
        merged_cves = MergeReports(
            merge_files=filepaths, error_mode=ErrorMode.FullTrace, score=0
        )
        merge_cve_scanner = merged_cves.merge_intermediate()
        with CVEScanner(score=0) as cve_scanner:
            for product_info, triage_data in merged_data.items():
                cve_scanner.get_cves(product_info, triage_data)

            assert merge_cve_scanner.all_cve_data == cve_scanner.all_cve_data

    @pytest.mark.parametrize(
        "filepaths",
        (([str(INTERMEDIATE_PATH / "test_intermediate.json")]),),
    )
    def test_valid_cve_scanner_instance(self, filepaths):
        merged_cves = MergeReports(
            merge_files=filepaths,
            error_mode=ErrorMode.FullTrace,
        )
        merge_cve_scanner = merged_cves.merge_intermediate()

        assert isinstance(merge_cve_scanner, CVEScanner)
