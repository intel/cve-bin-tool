# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from typing import Dict

import pytest

from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.sbom_manager import Remarks, SBOMManager
from cve_bin_tool.util import ProductInfo


class TestSBOM:
    SBOM_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "sbom")
    PARSED_SBOM_DATA = {
        ProductInfo(vendor="gnu", product="glibc", version="2.11.1"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        }
    }

    @pytest.mark.parametrize(
        "filepath",
        (os.path.join(SBOM_PATH, "nonexistent.spdx.json"),),
    )
    def test_nonexistent_file(self, filepath: str):
        sbom_engine = SBOMManager(filepath)
        assert sbom_engine.scan_file() == {}

    @pytest.mark.parametrize(
        "filename, sbom_type",
        (
            ((os.path.join(SBOM_PATH, "bad.csv")), "spdx"),
            ((os.path.join(SBOM_PATH, "bad.csv")), "cyclonedx"),
            ((os.path.join(SBOM_PATH, "bad.csv")), "swid"),
        ),
    )
    def test_invalid_file(self, filename: str, sbom_type: str):
        sbom_engine = SBOMManager(filename, sbom_type)
        assert sbom_engine.scan_file() == {}

    @pytest.mark.parametrize(
        "filename, sbom_type",
        (
            ((os.path.join(SBOM_PATH, "bad.csv")), "sbom"),
            ((os.path.join(SBOM_PATH, "bad.csv")), "SPDX"),
        ),
    )
    def test_invalid_type(self, filename: str, sbom_type: str):
        sbom_engine = SBOMManager(filename, sbom_type)
        assert sbom_engine.scan_file() == {}

    @pytest.mark.parametrize(
        "filename, spdx_parsed_data",
        (
            (os.path.join(SBOM_PATH, "spdx_test.spdx"), PARSED_SBOM_DATA),
            (os.path.join(SBOM_PATH, "spdx_test.spdx.rdf"), PARSED_SBOM_DATA),
            (os.path.join(SBOM_PATH, "spdx_test.spdx.json"), PARSED_SBOM_DATA),
            (os.path.join(SBOM_PATH, "spdx_test.spdx.xml"), PARSED_SBOM_DATA),
            (os.path.join(SBOM_PATH, "spdx_test.spdx.yml"), PARSED_SBOM_DATA),
            (os.path.join(SBOM_PATH, "spdx_test.spdx.yaml"), PARSED_SBOM_DATA),
        ),
    )
    def test_valid_spdx_file(
        self, filename: str, spdx_parsed_data: Dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMManager(filename, sbom_type="spdx")
        assert sbom_engine.scan_file() == spdx_parsed_data

    @pytest.mark.parametrize(
        "filename, cyclonedx_parsed_data",
        (
            (os.path.join(SBOM_PATH, "cyclonedx_test.xml"), PARSED_SBOM_DATA),
            (os.path.join(SBOM_PATH, "cyclonedx_test.json"), PARSED_SBOM_DATA),
        ),
    )
    def test_valid_cyclonedx_file(
        self, filename: str, cyclonedx_parsed_data: Dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMManager(filename, sbom_type="cyclonedx")
        assert sbom_engine.scan_file() == cyclonedx_parsed_data

    @pytest.mark.parametrize(
        "filename, swid_parsed_data",
        ((os.path.join(SBOM_PATH, "swid_test.xml"), PARSED_SBOM_DATA),),
    )
    def test_valid_swid_file(
        self, filename: str, swid_parsed_data: Dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMManager(filename, sbom_type="swid")
        assert sbom_engine.scan_file() == swid_parsed_data
