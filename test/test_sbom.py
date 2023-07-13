# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import pytest

from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.sbom_manager import Remarks, SBOMManager
from cve_bin_tool.util import ProductInfo


class TestSBOM:
    SBOM_PATH = Path(__file__).parent.resolve() / "sbom"
    PARSED_SBOM_DATA = {
        ProductInfo(vendor="gnu", product="glibc", version="2.11.1"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        }
    }

    PARSED_SBOM_DATA2 = {
        ProductInfo(vendor="ubuntu", product="ubuntu", version="22.04"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        }
    }
    PARSED_SBOM_DATA3 = {
        ProductInfo(vendor="gnu", product="glibc", version="2.11.1"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="apache", product="jena", version="3.12.0"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="saxon", product="saxon", version="8.8"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
    }

    @pytest.mark.parametrize(
        "filepath",
        (str(SBOM_PATH / "nonexistent.spdx.json"),),
    )
    def test_nonexistent_file(self, filepath: str):
        sbom_engine = SBOMManager(filepath)
        assert sbom_engine.scan_file() == {}

    @pytest.mark.parametrize(
        "filename, sbom_type",
        (
            (str(SBOM_PATH / "bad.csv"), "spdx"),
            (str(SBOM_PATH / "bad.csv"), "cyclonedx"),
            (str(SBOM_PATH / "bad.csv"), "swid"),
        ),
    )
    def test_invalid_file(self, filename: str, sbom_type: str):
        sbom_engine = SBOMManager(filename, sbom_type)
        assert sbom_engine.scan_file() == {}

    @pytest.mark.parametrize(
        "filename, sbom_type",
        (
            (str(SBOM_PATH / "bad.csv"), "sbom"),
            (str(SBOM_PATH / "bad.csv"), "SPDX"),
        ),
    )
    def test_invalid_type(self, filename: str, sbom_type: str):
        sbom_engine = SBOMManager(filename, sbom_type)
        assert sbom_engine.scan_file() == {}

    @pytest.mark.parametrize(
        "filename, spdx_parsed_data",
        (
            (str(SBOM_PATH / "spdx_test.spdx"), PARSED_SBOM_DATA3),
            (str(SBOM_PATH / "spdx_test.spdx.rdf"), PARSED_SBOM_DATA3),
            (str(SBOM_PATH / "spdx_test.spdx.json"), PARSED_SBOM_DATA3),
            (str(SBOM_PATH / "spdx_test.spdx.xml"), PARSED_SBOM_DATA3),
            (str(SBOM_PATH / "spdx_test.spdx.yml"), PARSED_SBOM_DATA3),
            (str(SBOM_PATH / "spdx_test.spdx.yaml"), PARSED_SBOM_DATA3),
            (str(SBOM_PATH / "spdx_mixed_test.spdx.json"), PARSED_SBOM_DATA3),
        ),
    )
    def test_valid_spdx_file(
        self, filename: str, spdx_parsed_data: dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMManager(filename, sbom_type="spdx")
        scan_result = sbom_engine.scan_file()
        for p in spdx_parsed_data:
            assert p in scan_result

    @pytest.mark.parametrize(
        "filename, cyclonedx_parsed_data",
        (
            (str(SBOM_PATH / "cyclonedx_test.xml"), PARSED_SBOM_DATA),
            (str(SBOM_PATH / "cyclonedx_test.json"), PARSED_SBOM_DATA),
            (str(SBOM_PATH / "cyclonedx_test2.json"), PARSED_SBOM_DATA2),
            (str(SBOM_PATH / "cyclonedx_mixed_test.json"), PARSED_SBOM_DATA),
        ),
    )
    def test_valid_cyclonedx_file(
        self, filename: str, cyclonedx_parsed_data: dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMManager(filename, sbom_type="cyclonedx")
        scan_result = sbom_engine.scan_file()
        for p in cyclonedx_parsed_data:
            assert p in scan_result

    @pytest.mark.parametrize(
        "filename, swid_parsed_data",
        ((str(SBOM_PATH / "swid_test.xml"), PARSED_SBOM_DATA),),
    )
    def test_valid_swid_file(
        self, filename: str, swid_parsed_data: dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMManager(filename, sbom_type="swid")
        scan_result = sbom_engine.scan_file()
        for p in swid_parsed_data:
            assert p in scan_result

    @pytest.mark.parametrize(
        "filename, sbom_type, validate",
        (
            (str(SBOM_PATH / "swid_test.xml"), "spdx", True),
            (str(SBOM_PATH / "swid_test.xml"), "cyclondedx", True),
            (str(SBOM_PATH / "swid_test.xml"), "spdx", False),
            (str(SBOM_PATH / "swid_test.xml"), "cyclondedx", False),
            (str(SBOM_PATH / "cyclonedx_test.xml"), "spdx", True),
            (str(SBOM_PATH / "cyclonedx_test.xml"), "swid", True),
            (str(SBOM_PATH / "cyclonedx_test.xml"), "spdx", False),
            (str(SBOM_PATH / "cyclonedx_test.xml"), "swid", False),
            (str(SBOM_PATH / "spdx_test.spdx.xml"), "cyclonedx", True),
            (str(SBOM_PATH / "spdx_test.spdx.xml"), "swid", True),
            (str(SBOM_PATH / "spdx_test.spdx.xml"), "cyclonedx", False),
            (str(SBOM_PATH / "spdx_test.spdx.xml"), "swid", False),
        ),
    )
    def test_invalid_xml(self, filename: str, sbom_type: str, validate: bool):
        """
        Demonstrate that validation of XML file against schema results in no data
        if file does not match schema or if xml data is parsed against wrong type of sbom
        (indicated by validate being set to False)
        """
        sbom_engine = SBOMManager(filename, sbom_type, validate=validate)
        assert sbom_engine.scan_file() == {}
