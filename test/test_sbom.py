# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import pytest

from cve_bin_tool.input_engine import TriageData
from cve_bin_tool.sbom_manager.parse import SBOMParse
from cve_bin_tool.sbom_manager.sbom_detection import sbom_detection
from cve_bin_tool.util import ProductInfo, Remarks


class TestSBOM:
    SBOM_PATH = Path(__file__).parent.resolve() / "sbom"
    PARSED_SBOM_DATA = {
        ProductInfo(
            vendor="gnu", product="glibc", version="2.11.1", location="NotFound"
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        }
    }

    PARSED_SBOM_DATA2 = {
        ProductInfo(
            vendor="ubuntu", product="ubuntu", version="22.04", location="NotFound"
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        }
    }
    PARSED_SBOM_DATA3 = {
        ProductInfo(
            vendor="gnu", product="glibc", version="2.11.1", location="NotFound"
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(
            vendor="saxon", product="saxon", version="8.8", location="NotFound"
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
    }
    SPLIT_DATA = [
        ProductInfo(
            vendor="openzeppelin",
            product="contracts",
            version="4.8.1",
            location="NotFound",
        ),
        ProductInfo(
            vendor="downline_goldmine",
            product="builder",
            version="3.2.4",
            location="NotFound",
        ),
    ]

    PARSED_BAD_SBOM_DATA = [
        ProductInfo(
            vendor="UNKNOWN",
            product="libjpeg-novendor",
            version="8b",
            location="NotFound",
        ),
        ProductInfo(
            vendor="libexpat_project",
            product="libexpat",
            version="2.0.1",
            location="NotFound",
        ),
        ProductInfo(
            vendor="UNKNOWN",
            product="ncurses-noversion",
            version="5.9.noversion",
            location="NotFound",
        ),
        ProductInfo(
            vendor="zlib", product="zlib", version="1.2.3", location="NotFound"
        ),
    ]
    PARSED_EXT_REF_PRIORITY_SBOM_DATA = [
        ProductInfo(vendor="ijg", product="libjpeg", version="8b", location="NotFound"),
        ProductInfo(
            vendor="libexpat_project",
            product="libexpat",
            version="2.0.1",
            location="NotFound",
        ),
        ProductInfo(
            vendor="gnu", product="ncurses", version="5.9", location="NotFound"
        ),
        ProductInfo(
            vendor="unknown", product="ncurses", version="5.9", location="NotFound"
        ),
        ProductInfo(
            vendor="ncurses_project",
            product="ncurses",
            version="5.9",
            location="NotFound",
        ),
        ProductInfo(
            vendor="zlib", product="zlib", version="1.2.3", location="NotFound"
        ),
        ProductInfo(
            vendor="unknown", product="zlib", version="1.2.3", location="NotFound"
        ),
        ProductInfo(vendor="gnu", product="zlib", version="1.2.3", location="NotFound"),
    ]

    @pytest.mark.parametrize(
        "filepath",
        (str(SBOM_PATH / "nonexistent.spdx.json"),),
    )
    def test_nonexistent_file(self, filepath: str):
        sbom_engine = SBOMParse(filepath)
        assert sbom_engine.parse_sbom() == {}

    @pytest.mark.parametrize(
        "filename, sbom_type",
        (
            (str(SBOM_PATH / "bad.csv"), "spdx"),
            (str(SBOM_PATH / "bad.csv"), "cyclonedx"),
            (str(SBOM_PATH / "bad.csv"), "swid"),
        ),
    )
    def test_invalid_file(self, filename: str, sbom_type: str):
        sbom_engine = SBOMParse(filename, sbom_type)
        assert sbom_engine.parse_sbom() == {}

    @pytest.mark.parametrize(
        "filename, sbom_type",
        (
            (str(SBOM_PATH / "bad.csv"), "sbom"),
            (str(SBOM_PATH / "bad.csv"), "SPDX"),
        ),
    )
    def test_invalid_type(self, filename: str, sbom_type: str):
        sbom_engine = SBOMParse(filename, sbom_type)
        assert sbom_engine.parse_sbom() == {}

    @pytest.mark.skip(reason="Cache is broken, disabling temporarily")
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
        sbom_engine = SBOMParse(filename, sbom_type="spdx")
        scan_result = sbom_engine.parse_sbom()
        for p in spdx_parsed_data:
            assert p in scan_result

    @pytest.mark.skip(reason="Cache is broken, disabling temporarily")
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
        sbom_engine = SBOMParse(filename, sbom_type="cyclonedx")
        scan_result = sbom_engine.parse_sbom()
        for p in cyclonedx_parsed_data:
            assert p in scan_result

    @pytest.mark.skip(reason="Cache is broken, disabling temporarily")
    @pytest.mark.parametrize(
        "filename, cyclonedx_parsed_data",
        (
            (str(SBOM_PATH / "cyclonedx_bad_cpe22.json"), PARSED_BAD_SBOM_DATA),
            (str(SBOM_PATH / "cyclonedx_bad_cpe23.json"), PARSED_BAD_SBOM_DATA),
            (str(SBOM_PATH / "cyclonedx_bad_purl.json"), PARSED_BAD_SBOM_DATA),
        ),
    )
    def test_bad_ext_ref_cyclonedx_file(
        self, filename: str, cyclonedx_parsed_data: dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMParse(filename, sbom_type="cyclonedx")
        scan_result = sbom_engine.parse_sbom()
        for p in cyclonedx_parsed_data:
            assert p in scan_result.keys()

    @pytest.mark.skip(reason="Cache is broken, disabling temporarily")
    @pytest.mark.parametrize(
        "filename, cyclonedx_parsed_data",
        (
            (
                str(SBOM_PATH / "cyclonedx_ext_ref_priority.json"),
                PARSED_EXT_REF_PRIORITY_SBOM_DATA,
            ),
        ),
    )
    def test_ext_ref_priority_cyclonedx_file(
        self, filename: str, cyclonedx_parsed_data: dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMParse(filename, sbom_type="cyclonedx")
        scan_result = sbom_engine.parse_sbom()
        for p in cyclonedx_parsed_data:
            assert p in scan_result.keys()

    @pytest.mark.parametrize(
        "filename, swid_parsed_data",
        ((str(SBOM_PATH / "swid_test.xml"), PARSED_SBOM_DATA),),
    )
    def test_valid_swid_file(
        self, filename: str, swid_parsed_data: dict[ProductInfo, TriageData]
    ):
        sbom_engine = SBOMParse(filename, sbom_type="swid")
        scan_result = sbom_engine.parse_sbom()
        for p in swid_parsed_data:
            assert p in scan_result

    @pytest.mark.skip(reason="Cache is broken, disabling temporarily")
    @pytest.mark.parametrize(
        "product, version, productinfo, no_existent_file",
        [
            ("openzeppelin-contracts", "4.8.1", SPLIT_DATA[0], "no_existent_file"),
            ("rubygem-builder", "3.2.4", SPLIT_DATA[1], "no_existent_file"),
        ],
    )
    def test_common_prefix_split(self, product, version, productinfo, no_existent_file):
        """Unit Test for common_prefix_split that try to split on hyphen if no vendors are
        are found and the product has hyphen, here a no_existent_file is used
        with sole purpose for creating a SBOMParse instance"""
        sbom_engine = SBOMParse(no_existent_file)
        scanned_list = sbom_engine.common_prefix_split(product, version)
        assert productinfo in scanned_list

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
        sbom_engine = SBOMParse(filename, sbom_type, validate=validate)
        assert sbom_engine.parse_sbom() == {}

    @pytest.mark.parametrize(
        "filename, expected_sbom_type",
        (
            (str(SBOM_PATH / "cyclonedx_test.json"), "cyclonedx"),
            (str(SBOM_PATH / "cyclonedx_test2.json"), "cyclonedx"),
            (str(SBOM_PATH / "cyclonedx_mixed_test.json"), "cyclonedx"),
            (str(SBOM_PATH / "cyclonedx_test.xml"), "cyclonedx"),
            (str(SBOM_PATH / "spdx_test.spdx"), "spdx"),
            (str(SBOM_PATH / "spdx_test.spdx.rdf"), "spdx"),
            (str(SBOM_PATH / "spdx_test.spdx.yaml"), "spdx"),
            (str(SBOM_PATH / "spdx_test.spdx.rdf"), "spdx"),
            (str(SBOM_PATH / "spdx_test.spdx.yml"), "spdx"),
            (str(SBOM_PATH / "spdx_mixed_test.spdx.json"), "spdx"),
            (str(SBOM_PATH / "swid_test.xml"), "swid"),
            (str(SBOM_PATH / "bad.csv"), None),
        ),
    )
    def test_sbom_detection(self, filename: str, expected_sbom_type: str):
        assert sbom_detection(filename) == expected_sbom_type
