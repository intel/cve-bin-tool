# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool OutputEngine tests
"""
import csv
import importlib.util
import json
import logging
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import requests
from jsonschema import validate
from rich.console import Console

from cve_bin_tool.output_engine import OutputEngine, output_csv, output_json, output_pdf
from cve_bin_tool.output_engine.console import output_console
from cve_bin_tool.output_engine.util import format_output
from cve_bin_tool.util import CVE, CVEData, ProductInfo, VersionInfo

VEX_SCHEMA = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json"


class TestOutputEngine(unittest.TestCase):
    """Test the OutputEngine class functions"""

    MOCK_DETAILED_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    description="description0",
                    data_source="NVD",
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    description="description1",
                    data_source="NVD",
                )
            ],
            paths={""},
        ),
    }

    FORMATTED_DETAILED_OUTPUT = [
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-1234-1234",
            "source": "NVD",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
            "description": "description0",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "2.8.6",
            "cve_number": "CVE-1234-1234",
            "source": "NVD",
            "severity": "LOW",
            "score": "2.5",
            "cvss_version": "3",
            "cvss_vector": "CVSS3.0/C:H/I:L/A:M",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
            "description": "description1",
        },
    ]

    MOCK_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-1234-1234",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    data_source="NVD",
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    data_source="NVD",
                )
            ],
            paths={""},
        ),
        ProductInfo("vendor1", "product1", "3.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    data_source="NVD",
                )
            ],
            paths={""},
        ),
    }

    MOCK_PDF_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-1234-1234",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    data_source="NVD",
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    data_source="NVD",
                )
            ],
            paths={""},
        ),
        ProductInfo("vendor1", "product1", "3.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1234",
                    "unknown",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    data_source="NVD",
                )
            ],
            paths={""},
        ),
    }

    MOCK_ALL_CVE_DATA = {
        ProductInfo("vendor0", "product0", "1.0"): CVEData(
            cves=[
                CVE(
                    "UNKNOWN",
                    "UNKNOWN",
                    score=0,
                    cvss_version=0,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0001",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0002",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0003",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0004",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0005",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0006",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0007",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-0008",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                ),
                CVE(
                    "CVE-9999-9999",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    data_source="NVD",
                ),
            ],
            paths={""},
        ),
    }

    MOCK_ALL_CVE_VERSION_INFO = {
        "UNKNOWN": VersionInfo("", "", "", ""),
        "CVE-9999-0001": VersionInfo("0.9.0", "", "1.2.0", ""),
        "CVE-9999-0002": VersionInfo("0.9.0", "", "", "1.2.0"),
        "CVE-9999-0003": VersionInfo("", "0.9.0", "1.2.0", ""),
        "CVE-9999-0004": VersionInfo("", "0.9.0", "", "1.2.0"),
        "CVE-9999-0005": VersionInfo("0.9.0", "", "", ""),
        "CVE-9999-0006": VersionInfo("", "0.9.0", "", ""),
        "CVE-9999-0007": VersionInfo("", "", "1.2.0", ""),
        "CVE-9999-0008": VersionInfo("", "", "", "1.2.0"),
    }

    FORMATTED_OUTPUT = [
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-1234-1234",
            "source": "NVD",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-1234-1234",
            "source": "NVD",
            "severity": "LOW",
            "score": "1.2",
            "cvss_version": "2",
            "cvss_vector": "CVSS2.0/C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "2.8.6",
            "cve_number": "CVE-1234-1234",
            "source": "NVD",
            "severity": "LOW",
            "score": "2.5",
            "cvss_version": "3",
            "cvss_vector": "CVSS3.0/C:H/I:L/A:M",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor1",
            "product": "product1",
            "version": "3.2.1.0",
            "cve_number": "CVE-1234-1234",
            "source": "NVD",
            "severity": "HIGH",
            "score": "7.5",
            "cvss_version": "2",
            "cvss_vector": "C:H/I:L/A:M",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
    ]

    FORMATTED_OUTPUT_AFFECTED_VERSIONS = [
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "UNKNOWN",
            "severity": "UNKNOWN",
            "score": "0",
            "cvss_version": "0",
            "affected_versions": "-",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0001",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": "[0.9.0 - 1.2.0]",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0002",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": "[0.9.0 - 1.2.0)",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0003",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": "(0.9.0 - 1.2.0]",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0004",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": "(0.9.0 - 1.2.0)",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0005",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": ">= 0.9.0",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0006",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": "> 0.9.0",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0007",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": "<= 1.2.0",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-0008",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "affected_versions": "< 1.2.0",
            "cvss_vector": "C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "cve_number": "CVE-9999-9999",
            "severity": "LOW",
            "score": "1.2",
            "cvss_version": "2",
            "affected_versions": "-",
            "cvss_vector": "CVSS2.0/C:H",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
    ]

    HTML_CVE_SUMMARY_TABLE = """                    <thead>
                        <tr>
                            <th scope="col">Severity</th>
                            <th scope="col">Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr class="table-danger">
                            <th scope="row">CRITICAL</th>
                            <td>0</td>
                        </tr>
                        <tr class="table-primary">
                            <th scope="row">HIGH</th>
                            <td>1</td>
                        </tr>
                        <tr class="table-warning">
                            <th scope="row">MEDIUM</th>
                            <td>1</td>
                        </tr>
                        <tr class="table-success">
                            <th scope="row">LOW</th>
                            <td>2</td>
                        </tr>
                    </tbody>"""

    HTML_CVE_REMARK_TABLE = """                    <thead>
                        <tr>
                            <th scope="col">Remark</th>
                            <th scope="col">Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <th scope="row">NEW</th>
                            <td>4</td>
                        </tr>
                        <tr>
                            <th scope="row">CONFIRMED</th>
                            <td>0</td>
                        </tr>
                        <tr>
                            <th scope="row">MITIGATED</th>
                            <td>0</td>
                        </tr>
                        <tr>
                            <th scope="row">UNEXPLORED</th>
                            <td>0</td>
                        </tr>
                        <tr>
                            <th scope="row">IGNORED</th>
                            <td>0</td>
                        </tr>
                    </tbody>"""

    PDF_OUTPUT = (
        "3. List of Identified Vulnerabilities"
        "The following vulnerabilities are reported against the identified versions of the"
        "components."
        "3.1 New Found CVEs"
        "Vendor"
        "Product"
        "Version"
        "CVE Number"
        "Source"
        "Severity"
        "vendor0"
        "product0"
        "1.0"
        "CVE-1234-1234"
        "NVD"
        "MEDIUM"
        "vendor0"
        "product0"
        "1.0"
        "CVE-1234-1234"
        "NVD"
        "LOW"
        "vendor0"
        "product0"
        "2.8.6"
        "CVE-1234-1234"
        "NVD"
        "LOW"
        "vendor1"
        "product1"
        "3.2.1.0"
        "CVE-1234-1234"
        "NVD"
        "unknown"
        "The following vulnerabilities are reported against the identified components which"
        "contain the reported components."
        "Vendor"
        "Product"
        "Version"
        "Root"
        "Filename"
        "vendor0"
        "product0"
        "1.0"
        "vendor0"
        "product0"
        "2.8.6"
        "vendor1"
        "product1"
        "3.2.1.0"
        "Page 2"
    )

    VEX_FORMATTED_OUTPUT = [
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "vulnerabilities": [
                {
                    "id": "CVE-1234-1234",
                    "source": {
                        "name": "NVD",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-1234-1234",
                    },
                    "ratings": [
                        {
                            "source": {
                                "name": "NVD",
                                "url": "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=CVE-1234-1234&vector=C:H&version=2.0",
                            },
                            "score": 4.2,
                            "severity": "medium",
                            "method": "CVSSv2",
                            "vector": "C:H",
                        }
                    ],
                    "cwes": [],
                    "description": "",
                    "recommendation": "",
                    "advisories": [],
                    "created": "NOT_KNOWN",
                    "published": "NOT_KNOWN",
                    "updated": "NOT_KNOWN",
                    "analysis": {
                        "state": "in_triage",
                        "response": [],
                        "detail": "NewFound",
                    },
                    "affects": [{"ref": "urn:cdx:NOTKNOWN/1#product0-1.0"}],
                },
                {
                    "id": "CVE-1234-1234",
                    "source": {
                        "name": "NVD",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-1234-1234",
                    },
                    "ratings": [
                        {
                            "source": {
                                "name": "NVD",
                                "url": "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=CVE-1234-1234&vector=CVSS2.0/C:H&version=2.0",
                            },
                            "score": 1.2,
                            "severity": "low",
                            "method": "CVSSv2",
                            "vector": "CVSS2.0/C:H",
                        }
                    ],
                    "cwes": [],
                    "description": "",
                    "recommendation": "",
                    "advisories": [],
                    "created": "NOT_KNOWN",
                    "published": "NOT_KNOWN",
                    "updated": "NOT_KNOWN",
                    "analysis": {
                        "state": "in_triage",
                        "response": [],
                        "detail": "NewFound",
                    },
                    "affects": [{"ref": "urn:cdx:NOTKNOWN/1#product0-1.0"}],
                },
                {
                    "id": "CVE-1234-1234",
                    "source": {
                        "name": "NVD",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-1234-1234",
                    },
                    "ratings": [
                        {
                            "source": {
                                "name": "NVD",
                                "url": "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=CVE-1234-1234&vector=CVSS3.0/C:H/I:L/A:M&version=3.1",
                            },
                            "score": 2.5,
                            "severity": "low",
                            "method": "CVSSv3",
                            "vector": "CVSS3.0/C:H/I:L/A:M",
                        }
                    ],
                    "cwes": [],
                    "description": "",
                    "recommendation": "",
                    "advisories": [],
                    "created": "NOT_KNOWN",
                    "published": "NOT_KNOWN",
                    "updated": "NOT_KNOWN",
                    "analysis": {
                        "state": "in_triage",
                        "response": [],
                        "detail": "NewFound",
                    },
                    "affects": [{"ref": "urn:cdx:NOTKNOWN/1#product0-2.8.6"}],
                },
                {
                    "id": "CVE-1234-1234",
                    "source": {
                        "name": "NVD",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-1234-1234",
                    },
                    "ratings": [
                        {
                            "source": {
                                "name": "NVD",
                                "url": "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=CVE-1234-1234&vector=C:H/I:L/A:M&version=2.0",
                            },
                            "score": 7.5,
                            "severity": "high",
                            "method": "CVSSv2",
                            "vector": "C:H/I:L/A:M",
                        }
                    ],
                    "cwes": [],
                    "description": "",
                    "recommendation": "",
                    "advisories": [],
                    "created": "NOT_KNOWN",
                    "published": "NOT_KNOWN",
                    "updated": "NOT_KNOWN",
                    "analysis": {
                        "state": "in_triage",
                        "response": [],
                        "detail": "NewFound",
                    },
                    "affects": [{"ref": "urn:cdx:NOTKNOWN/1#product1-3.2.1.0"}],
                },
            ],
        }
    ]

    def setUp(self) -> None:
        self.output_engine = OutputEngine(
            all_cve_data=self.MOCK_OUTPUT,
            scanned_dir="",
            filename="",
            themes_dir="",
            time_of_last_update=datetime.today(),
            tag="",
        )
        self.mock_file = tempfile.NamedTemporaryFile("w+", encoding="utf-8")

    def tearDown(self) -> None:
        self.mock_file.close()

    def test_formatted_output(self):
        """Test reformatting products"""
        self.assertEqual(format_output(self.MOCK_OUTPUT, None), self.FORMATTED_OUTPUT)

    def test_formatted_detailed_output(self):
        """Test detailed flag output"""
        self.assertEqual(
            format_output(self.MOCK_DETAILED_OUTPUT, None, detailed=True),
            self.FORMATTED_DETAILED_OUTPUT,
        )

    def test_output_json(self):
        """Test formatting output as JSON"""
        output_json(self.MOCK_OUTPUT, None, self.mock_file)
        self.mock_file.seek(0)  # reset file position
        self.assertEqual(json.load(self.mock_file), self.FORMATTED_OUTPUT)

    def test_output_csv(self):
        """Test formatting output as CSV"""
        output_csv(self.MOCK_OUTPUT, None, self.mock_file)
        self.mock_file.seek(0)  # reset file position
        reader = csv.DictReader(self.mock_file)
        expected_value = [dict(x) for x in reader]
        self.assertEqual(expected_value, self.FORMATTED_OUTPUT)

    def test_output_vex(self):
        """Test creating VEX formatted file"""
        self.output_engine.generate_vex(self.MOCK_OUTPUT, "test.vex")
        with open("test.vex") as f:
            vex_json = json.load(f)
            SCHEMA = requests.get(VEX_SCHEMA).json()
            validate(vex_json, SCHEMA)
            self.assertEqual(vex_json, self.VEX_FORMATTED_OUTPUT[0])
        Path("test.vex").unlink()

    @unittest.skipUnless(
        importlib.util.find_spec("reportlab") is not None
        and importlib.util.find_spec("pdftotext") is not None,
        "Skipping PDF tests. Please install reportlab and pdftotext to run these tests.",
    )
    def test_output_pdf(self):
        """Test formatting output as PDF"""
        import pdftotext

        output_pdf(self.MOCK_PDF_OUTPUT, False, 1, None, "cve_test.pdf", False, 0)
        with open("cve_test.pdf", "rb") as f:
            pdf = pdftotext.PDF(f, physical=True)
            # Only interested in section 3 of the report which contains table of CVEs. This is on the second page
            page = pdf[1]
            # Find start of section 3 header
            section2_start = page.find("3. List of Identified Vulnerabilities")
        self.assertEqual(
            page[section2_start:]
            .replace(" ", "")
            .replace("\r", "")
            .replace("\n", "")
            .strip(),
            self.PDF_OUTPUT.replace(" ", ""),
        )

    def test_output_console(self):
        """Test Formatting Output as console"""

        time_of_last_update = datetime.today()
        affected_versions = 0
        exploits = False
        console = Console(file=self.mock_file)
        outfile = None
        all_product_data = None

        output_console(
            self.MOCK_OUTPUT,
            self.MOCK_ALL_CVE_VERSION_INFO,
            time_of_last_update,
            affected_versions,
            exploits,
            all_product_data,
            console,
            outfile,
        )

        expected_output = (
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1234 │ NVD    │ MEDIUM   │ 4.2 (v2)             │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1234 │ NVD    │ LOW      │ 1.2 (v2)             │\n"
            "│ vendor0 │ product0 │ 2.8.6   │ CVE-1234-1234 │ NVD    │ LOW      │ 2.5 (v3)             │\n"
            "│ vendor1 │ product1 │ 3.2.1.0 │ CVE-1234-1234 │ NVD    │ HIGH     │ 7.5 (v2)             │\n"
            "└─────────┴──────────┴─────────┴───────────────┴────────┴──────────┴──────────────────────┘\n"
        )

        self.mock_file.seek(0)  # reset file position
        result = self.mock_file.read()
        self.assertIn(expected_output, result)

    def test_output_console_affected_versions(self):
        """Test Formatting Output as console with affected-versions"""

        time_of_last_update = datetime.today()
        affected_versions = 1
        exploits = False
        console = Console(file=self.mock_file)
        outfile = None
        all_product_data = None

        output_console(
            self.MOCK_ALL_CVE_DATA,
            self.MOCK_ALL_CVE_VERSION_INFO,
            time_of_last_update,
            affected_versions,
            exploits,
            all_product_data,
            console,
            outfile,
        )

        expected_output = (
            "│ vendor0 │ product0 │ 1.0     │ UNKNOWN       │ NVD    │ UNKNOWN  │ 0 (v0)               │ -                 │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0001 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ [0.9.0 - 1.2.0]   │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0002 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ [0.9.0 - 1.2.0)   │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0003 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ (0.9.0 - 1.2.0]   │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0004 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ (0.9.0 - 1.2.0)   │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0005 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ >= 0.9.0          │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0006 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ > 0.9.0           │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0007 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ <= 1.2.0          │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0008 │ NVD    │ MEDIUM   │ 4.2 (v2)             │ < 1.2.0           │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-9999 │ NVD    │ LOW      │ 1.2 (v2)             │ -                 │\n"
            "└─────────┴──────────┴─────────┴───────────────┴────────┴──────────┴──────────────────────┴───────────────────┘\n"
        )

        self.mock_file.seek(0)  # reset file position
        result = self.mock_file.read()
        self.assertIn(expected_output, result)

    def test_output_console_outfile(self):
        """Test output to a file"""

        tmpf = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8")
        tmpf.close()  # accessing open tempfile on windows gives error

        time_of_last_update = datetime.today()
        affected_versions = 0
        exploits = False
        outfile = tmpf.name
        all_product_data = None

        output_console(
            self.MOCK_OUTPUT,
            self.MOCK_ALL_CVE_VERSION_INFO,
            time_of_last_update,
            affected_versions,
            exploits,
            all_product_data,
            outfile,
        )

        expected_output = (
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1234 │ NVD    │ MEDIUM   │ 4.2 (v2)             │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1234 │ NVD    │ LOW      │ 1.2 (v2)             │\n"
            "│ vendor0 │ product0 │ 2.8.6   │ CVE-1234-1234 │ NVD    │ LOW      │ 2.5 (v3)             │\n"
            "│ vendor1 │ product1 │ 3.2.1.0 │ CVE-1234-1234 │ NVD    │ HIGH     │ 7.5 (v2)             │\n"
            "└─────────┴──────────┴─────────┴───────────────┴────────┴──────────┴──────────────────────┘\n"
        )

        with open(tmpf.name, encoding="utf-8") as f:
            result = f.read()

        self.assertIn(expected_output, result)
        Path(tmpf.name).unlink()  # deleting tempfile

    def test_output_file(self):
        """Test file generation logic in output_file"""
        logger = logging.getLogger()

        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="json")

        contains_filename = False
        contains_msg = False

        filename = Path(self.output_engine.filename)

        if filename.is_file():
            contains_filename = True

        if "JSON report stored at" in cm.output[0]:
            contains_msg = True

        # reset everything back
        filename.unlink()
        self.output_engine.filename = ""

        self.assertEqual(contains_filename, True)
        self.assertEqual(contains_msg, True)

    def test_output_file_wrapper(self):
        """Test file generation logic in output_file_wrapper"""
        logger = logging.getLogger()
        self.output_engine.filename = "test-report"

        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file_wrapper(output_types=["json", "html"])

        html_file = Path("test-report.html")
        json_file = Path("test-report.json")

        if html_file.is_file() and json_file.is_file():
            contains_filename = True
        else:
            contains_filename = False

        if (
            "JSON report stored at" in cm.output[0]
            and "HTML report stored at" in cm.output[1]
        ):
            contains_msg = True
        else:
            contains_msg = False

        # reset everything back
        html_file.unlink()
        json_file.unlink()
        self.output_engine.filename = ""

        self.assertEqual(contains_filename, True)
        self.assertEqual(contains_msg, True)

    def test_output_file_filename_already_exists(self):
        """Tests output_file when filename already exist"""

        # update the filename in output_engine
        self.output_engine.filename = "testfile.csv"

        # create a file with the same name as output_engine.filename
        with open("testfile.csv", "w") as f:
            f.write("testing")

        logger = logging.getLogger()

        # setup the context manager
        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="csv")

        # logs to check in cm
        msg_generate_filename = (
            "Generating a new filename with Default Naming Convention"
        )
        msg_failed_to_write = "Failed to write at 'testfile.csv'. File already exists"

        # flags for logs
        contains_fail2write = False
        contains_gen_file = False

        # check if the logger contains msg
        for log in cm.output:
            if msg_generate_filename in log:
                contains_gen_file = True
            elif msg_failed_to_write in log:
                contains_fail2write = True

        # remove the generated files and reset updated variables
        Path("testfile.csv").unlink()
        Path(self.output_engine.filename).unlink()
        self.output_engine.filename = ""

        # assert
        self.assertEqual(contains_gen_file, True)
        self.assertEqual(contains_fail2write, True)

    def test_output_file_incorrect_filename(self):
        """Tests filenames that are incorrect or are not accessible"""

        # update the filename in output_engine
        self.output_engine.filename = "/not/a/good_filename"

        logger = logging.getLogger()

        # setup the context manager
        with self.assertLogs(logger, logging.INFO) as cm:
            self.output_engine.output_file(output_type="csv")

        # log to check
        msg_switch_back = "Switching Back to Default Naming Convention"

        # flags
        contains_sb = False

        for log in cm.output:
            if msg_switch_back in log:
                contains_sb = True

        # remove the generated files and reset updated variables
        Path(self.output_engine.filename).unlink()
        self.output_engine.filename = ""

        # assert
        self.assertEqual(contains_sb, True)

    def test_csv_macros(self):
        """tests that output engine will not output leading -, =, +, @, tab or CR
        characters, used in spreadsheet macros"""

        bad_input = {
            ProductInfo("=vendor0", "\t+product0", "@1.0"): CVEData(
                cves=[
                    CVE(
                        "-CVE-1234-1234",
                        "\t\r@-=+MEDIUM",
                        score=4.2,
                        cvss_version=2,
                        cvss_vector="\rC:H",
                        data_source="NVD",
                    ),
                ],
                paths={"@@@@bad"},
            ),
        }
        expected_output = [
            {
                "vendor": "vendor0",
                "product": "product0",
                "version": "1.0",
                "cve_number": "CVE-1234-1234",
                "source": "NVD",
                "severity": "MEDIUM",
                "score": "4.2",
                "cvss_version": "2",
                "cvss_vector": "C:H",
                "paths": "bad",
                "remarks": "NewFound",
                "comments": "",
            },
        ]

        output_csv(bad_input, None, self.mock_file)
        self.mock_file.seek(0)  # reset file position
        reader = csv.DictReader(self.mock_file)
        actual_output = [dict(x) for x in reader]
        self.assertEqual(actual_output, expected_output)
