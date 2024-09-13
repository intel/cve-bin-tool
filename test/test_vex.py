# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import pytest

from cve_bin_tool.util import CVE, CVEData, ProductInfo, Remarks
from cve_bin_tool.vex_manager.generate import VEXGenerate
from cve_bin_tool.vex_manager.parse import VEXParse

TEMP_DIR = Path(tempfile.mkdtemp(prefix="test_triage-"))
TEST_DIR = Path(__file__).parent.resolve()
VEX_PATH = TEST_DIR / "vex"
SBOM_PATH = TEST_DIR / "sbom"
OUTPUT_JSON = str(TEMP_DIR / "test_triage_output.json")


class TestVexGeneration(unittest.TestCase):
    FORMATTED_DATA = {
        ProductInfo("vendor0", "product0", "1.0", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1004",
                    "CRITICAL",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    last_modified="01-05-2019",
                    metric={
                        "EPSS": [0.00126, "0.46387"],
                    },
                ),
                CVE(
                    "CVE-1234-1005",
                    "MEDIUM",
                    remarks=Remarks.NotAffected,
                    comments="Detail field populated.",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    last_modified="01-05-2019",
                    metric={
                        "EPSS": [0.00126, "0.46387"],
                    },
                    justification="code_not_reachable",
                    response=["will_not_fix"],
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1007",
                    "LOW",
                    remarks=Remarks.Mitigated,
                    comments="Data field populated.",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    data_source="NVD",
                    last_modified="12-12-2020",
                    metric={
                        "EPSS": [0.03895, "0.37350"],
                    },
                ),
                CVE(
                    "CVE-1234-1008",
                    "UNKNOWN",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    data_source="NVD",
                    last_modified="12-12-2020",
                    metric={
                        "EPSS": [0.03895, "0.37350"],
                    },
                ),
            ],
            paths={""},
        ),
    }

    def test_output_cyclonedx(self):
        """Test VEX output generation"""

        vexgen = VEXGenerate(
            "dummy-product",
            "1.0",
            "dummy-vendor",
            "generated_cyclonedx_vex.json",
            "cyclonedx",
            self.FORMATTED_DATA,
        )
        vexgen.generate_vex()
        with open("generated_cyclonedx_vex.json") as f:
            json_data = json.load(f)
            # remove timestamp and serialNumber from generated json as they are dynamic
            json_data.get("metadata", {}).pop("timestamp", None)
            json_data.pop("serialNumber", None)
            for vulnerability in json_data.get("vulnerabilities", []):
                vulnerability.pop("published", None)
                vulnerability.pop("updated", None)

        with open(str(VEX_PATH / "test_cyclonedx_vex.json")) as f:
            expected_json = json.load(f)
            # remove timestamp and serialNumber from expected json as they are dynamic
            expected_json.get("metadata", {}).pop("timestamp", None)
            expected_json.pop("serialNumber", None)
            for vulnerability in expected_json.get("vulnerabilities", []):
                vulnerability.pop("published", None)
                vulnerability.pop("updated", None)

        assert json_data == expected_json

        Path("generated_cyclonedx_vex.json").unlink()

    def test_output_openvex(self):
        """Test VEX output generation"""

        vexgen = VEXGenerate(
            "dummy-product",
            "1.0",
            "dummy-vendor",
            "generated_openvex_vex.json",
            "openvex",
            self.FORMATTED_DATA,
        )
        vexgen.generate_vex()

        with open("generated_openvex_vex.json") as f:
            json_data = json.load(f)
            # remove dynamic fields such as timestamp and id
            json_data.pop("@id", None)
            json_data.pop("timestamp", None)
            for statement in json_data.get("statements", []):
                statement.pop("timestamp", None)
                statement.pop("action_statement_timestamp", None)

        with open(str(VEX_PATH / "test_openvex_vex.json")) as f:
            expected_json = json.load(f)
            # remove dynamic fields such as timestamp and id
            expected_json.pop("@id", None)
            expected_json.pop("timestamp", None)
            for statement in expected_json.get("statements", []):
                statement.pop("timestamp", None)
                statement.pop("action_statement_timestamp", None)

        assert json_data == expected_json

        Path("generated_openvex_vex.json").unlink()


class TestVexParse:
    PARSED_DATA_WITH_PURL = {
        ProductInfo(
            vendor="vendor0",
            product="product0",
            version="1.0",
            location="location/to/product",
            purl="pkg:generic/vendor0/product0@1.0",
        ): {
            "CVE-1234-1004": {
                "remarks": Remarks.NewFound,
                "comments": "",
                "response": [],
            },
            "CVE-1234-1005": {
                "remarks": Remarks.NotAffected,
                "comments": "Detail field populated.",
                "response": [],
            },
            "paths": {},
        },
        ProductInfo(
            vendor="vendor0",
            product="product0",
            version="2.8.6",
            location="location/to/product",
            purl="pkg:generic/vendor0/product0@2.8.6",
        ): {
            "CVE-1234-1007": {
                "remarks": Remarks.Mitigated,
                "comments": "Data field populated.",
                "response": [],
            },
            "CVE-1234-1008": {
                "remarks": Remarks.NewFound,
                "comments": "",
                "response": [],
            },
            "paths": {},
        },
    }
    PARSED_DATA_WITHOUT_PURL = {
        ProductInfo(
            vendor="vendor0",
            product="product0",
            version="1.0",
            location="location/to/product",
        ): {
            "CVE-1234-1004": {
                "remarks": Remarks.NewFound,
                "comments": "",
                "response": [],
            },
            "CVE-1234-1005": {
                "remarks": Remarks.NotAffected,
                "comments": "code_not_reachable: NotAffected: Detail field populated.",
                "response": "will_not_fix",
                "justification": "code_not_reachable",
            },
            "paths": {},
        },
        ProductInfo(
            vendor="vendor0",
            product="product0",
            version="2.8.6",
            location="location/to/product",
        ): {
            "CVE-1234-1007": {
                "remarks": Remarks.Mitigated,
                "comments": "Data field populated.",
                "response": [],
            },
            "CVE-1234-1008": {
                "remarks": Remarks.NewFound,
                "comments": "",
                "response": [],
            },
            "paths": {},
        },
    }

    @pytest.mark.parametrize(
        "vex_format, vex_filename, expected_parsed_data",
        [
            ("cyclonedx", "test_cyclonedx_vex.json", PARSED_DATA_WITHOUT_PURL),
        ],
    )
    def test_parse_cyclonedx(self, vex_format, vex_filename, expected_parsed_data):
        """Test parsing of CycloneDX VEX"""
        vexparse = VEXParse(str(VEX_PATH / vex_filename), vex_format)
        parsed_data = vexparse.parse_vex()
        assert parsed_data == expected_parsed_data

    @pytest.mark.parametrize(
        "vex_format, vex_filename, expected_parsed_data",
        [
            ("openvex", "test_openvex_vex.json", PARSED_DATA_WITH_PURL),
        ],
    )
    def test_parse_openvex(self, vex_format, vex_filename, expected_parsed_data):
        """Test parsing of OpenVEX VEX"""
        vexparse = VEXParse(str(VEX_PATH / vex_filename), vex_format)
        parsed_data = vexparse.parse_vex()
        assert parsed_data == expected_parsed_data


class TestTriage:
    """Test triage functionality"""

    TEST_SBOM = str(SBOM_PATH / "test_triage_cyclonedx_sbom.json")
    TEST_VEX = str(VEX_PATH / "test_triage_cyclonedx_vex.json")

    def test_triage(self):
        """Test triage functionality"""
        subprocess.run(
            [
                "python",
                "-m",
                "cve_bin_tool.cli",
                "--sbom",
                "cyclonedx",
                "--sbom-file",
                self.TEST_SBOM,
                "--vex-file",
                self.TEST_VEX,
                "--format",
                "json",
                "--output-file",
                OUTPUT_JSON,
            ]
        )

        with open(OUTPUT_JSON) as f:
            output_json = json.load(f)
            assert len(output_json) >= 1
            for output in output_json:
                if output.get("cve_number", "") == "CVE-2023-39137":
                    assert output["remarks"] == "NotAffected"
                else:
                    assert output["remarks"] == "NewFound"
        Path(OUTPUT_JSON).unlink()

    def test_filter_triage(self):
        """Test filter triage functionality"""
        subprocess.run(
            [
                "python",
                "-m",
                "cve_bin_tool.cli",
                "--filter-triage",
                "--sbom",
                "cyclonedx",
                "--sbom-file",
                self.TEST_SBOM,
                "--vex-file",
                self.TEST_VEX,
                "--format",
                "json",
                "--output-file",
                OUTPUT_JSON,
            ]
        )

        with open(OUTPUT_JSON) as f:
            output_json = json.load(f)
            assert len(output_json) >= 1
            print("Output JSON:", output_json)
            for output in output_json:
                assert output.get("cve_number", "") != "CVE-2023-39137"
        Path(OUTPUT_JSON).unlink()


if __name__ == "__main__":
    unittest.main()
