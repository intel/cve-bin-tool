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
from unittest.mock import MagicMock, call, patch

from rich.console import Console

from cve_bin_tool.output_engine import OutputEngine, output_csv, output_pdf
from cve_bin_tool.output_engine.console import output_console
from cve_bin_tool.output_engine.json_output import output_json
from cve_bin_tool.output_engine.util import format_output
from cve_bin_tool.sbom_manager.generate import SBOMGenerate
from cve_bin_tool.util import CVE, CVEData, ProductInfo, Remarks, VersionInfo


class TestOutputEngine(unittest.TestCase):
    """Test the OutputEngine class functions"""

    MOCK_DETAILED_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1000",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    description="description0",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.00126, "0.46387"],
                    },
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1001",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    description="description1",
                    data_source="NVD",
                    metric={},
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
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1000",
            "source": "NVD",
            "severity": "MEDIUM",
            "score": "4.2",
            "cvss_version": "2",
            "cvss_vector": "C:H",
            "epss_probability": "0.00126",
            "epss_percentile": "0.46387",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
            "description": "description0",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "2.8.6",
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1001",
            "source": "NVD",
            "severity": "LOW",
            "score": "2.5",
            "cvss_version": "3",
            "cvss_vector": "CVSS3.0/C:H/I:L/A:M",
            "epss_probability": "-",
            "epss_percentile": "-",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
            "description": "description1",
        },
    ]

    MOCK_OUTPUT = {
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
                CVE(
                    "CVE-1234-1006",
                    "LOW",
                    # No remarks
                    comments="Data field populated.",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    data_source="NVD",
                    last_modified="11-11-2021",
                    metric={
                        "EPSS": [0.01836, "0.79673"],
                    },
                    justification="protected_by_mitigating_control",
                    response=["workaround_available"],
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
                    # No triage justification
                    # No triage response
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
                CVE(
                    "CVE-1234-1009",
                    "MEDIUM",
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
        ProductInfo(
            "vendor1", "product1", "3.2.1.0", "/usr/local/bin/product"
        ): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1010",
                    "HIGH",
                    # No remarks
                    # No comments
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    data_source="OSV",
                    last_modified="20-10-2012",
                    metric={
                        "EPSS": [0.0468, "0.34072"],
                    },
                    # No triage justification
                    # No triage response
                )
            ],
            paths={""},
        ),
    }

    MOCK_OUTPUT_2 = {
        ProductInfo("vendor0", "product0", "1.0", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1011",
                    "LOW",
                    score=6.4,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    last_modified="25-12-2023",
                ),
                CVE(
                    "CVE-1234-1012",
                    "MEDIUM",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    data_source="NVD",
                    last_modified="31-10-2021",
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.7", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1013",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    data_source="NVD",
                    last_modified="12-12-2020",
                )
            ],
            paths={""},
        ),
        ProductInfo("vendor1", "product1", "3.3.1", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1014",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    data_source="OSV",
                    last_modified="20-10-2012",
                )
            ],
            paths={""},
        ),
    }

    MOCK_PDF_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1015",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.6932, "0.2938"],
                    },
                ),
                CVE(
                    "CVE-1234-1016",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.06084, "0.7936"],
                    },
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1017",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.1646, "0.3955"],
                    },
                )
            ],
            paths={""},
        ),
        ProductInfo(
            "vendor1", "product1", "3.2.1.0", "/usr/local/bin/product"
        ): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1018",
                    "unknown",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    data_source="NVD",
                    metric={"EPSS": [0.2059, "0.09260"]},
                )
            ],
            paths={""},
        ),
    }

    MOCK_ALL_CVE_DATA = {
        ProductInfo("vendor0", "product0", "1.0", "/usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "UNKNOWN",
                    "UNKNOWN",
                    score=0,
                    cvss_version=0,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={},
                ),
                CVE(
                    "CVE-9999-0001",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.299, "0.25934"],
                    },
                ),
                CVE(
                    "CVE-9999-0002",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.0285, "0.94667"],
                    },
                ),
                CVE(
                    "CVE-9999-0003",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.0468, "0.34072"],
                    },
                ),
                CVE(
                    "CVE-9999-0004",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.35337, "0.72282"],
                    },
                ),
                CVE(
                    "CVE-9999-0005",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.15370, "0.21433"],
                    },
                ),
                CVE(
                    "CVE-9999-0006",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.0513, "0.77186"],
                    },
                ),
                CVE(
                    "CVE-9999-0007",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.08360, "0.53389"],
                    },
                ),
                CVE(
                    "CVE-9999-0008",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.36957, "0.83771"],
                    },
                ),
                CVE(
                    "CVE-9999-9999",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    data_source="NVD",
                    metric={
                        "EPSS": [0.012959, "0.67261"],
                    },
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
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1004",
            "severity": "CRITICAL",
            "score": "4.2",
            "source": "NVD",
            "cvss_version": "2",
            "cvss_vector": "C:H",
            "epss_probability": "0.00126",
            "epss_percentile": "0.46387",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1005",
            "severity": "MEDIUM",
            "score": "4.2",
            "source": "NVD",
            "cvss_version": "2",
            "cvss_vector": "C:H",
            "epss_probability": "0.00126",
            "epss_percentile": "0.46387",
            "paths": "",
            "remarks": "NotAffected",
            "response": ["will_not_fix"],
            "comments": "Detail field populated.",
            "justification": "code_not_reachable",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "1.0",
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1006",
            "severity": "LOW",
            "score": "1.2",
            "source": "NVD",
            "cvss_version": "2",
            "cvss_vector": "CVSS2.0/C:H",
            "epss_probability": "0.01836",
            "epss_percentile": "0.79673",
            "paths": "",
            "remarks": "NewFound",
            "comments": "Data field populated.",
            "justification": "protected_by_mitigating_control",
            "response": ["workaround_available"],
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "2.8.6",
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1007",
            "severity": "LOW",
            "score": "2.5",
            "source": "NVD",
            "cvss_version": "3",
            "cvss_vector": "CVSS3.0/C:H/I:L/A:M",
            "epss_probability": "0.03895",
            "epss_percentile": "0.37350",
            "paths": "",
            "remarks": "Mitigated",
            "comments": "Data field populated.",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "2.8.6",
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1008",
            "severity": "UNKNOWN",
            "score": "2.5",
            "source": "NVD",
            "cvss_version": "3",
            "cvss_vector": "CVSS3.0/C:H/I:L/A:M",
            "epss_probability": "0.03895",
            "epss_percentile": "0.37350",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor0",
            "product": "product0",
            "version": "2.8.6",
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1009",
            "severity": "MEDIUM",
            "score": "2.5",
            "source": "NVD",
            "cvss_version": "3",
            "cvss_vector": "CVSS3.0/C:H/I:L/A:M",
            "epss_probability": "0.03895",
            "epss_percentile": "0.37350",
            "paths": "",
            "remarks": "NewFound",
            "comments": "",
        },
        {
            "vendor": "vendor1",
            "product": "product1",
            "version": "3.2.1.0",
            "location": "/usr/local/bin/product",
            "cve_number": "CVE-1234-1010",
            "severity": "HIGH",
            "score": "7.5",
            "source": "OSV",
            "cvss_version": "2",
            "cvss_vector": "C:H/I:L/A:M",
            "epss_probability": "0.0468",
            "epss_percentile": "0.34072",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
            "location": "/usr/local/bin/product",
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
                            <th scope="row">FALSE POSITIVE</th>
                            <td>0</td>
                        </tr>
                        <tr>
                            <th scope="row">NOT AFFECTED</th>
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
        "CVE-1234-1015"
        "NVD"
        "MEDIUM"
        "vendor0"
        "product0"
        "1.0"
        "CVE-1234-1016"
        "NVD"
        "LOW"
        "vendor0"
        "product0"
        "2.8.6"
        "CVE-1234-1017"
        "NVD"
        "LOW"
        "vendor1"
        "product1"
        "3.2.1.0"
        "CVE-1234-1018"
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

    PDF_OUTPUT_2 = (
        "4. List of Vulnerabilities with different metric"
        "The table given below gives CVE found with there score on different metrics."
        "CVE Number"
        "CVSS_version"
        "CVSS_score"
        "EPSS_probability"
        "EPSS_percentile"
        "CVE-1234-1015"
        "2"
        "4.2"
        "0.6932"
        "0.2938"
        "CVE-1234-1016"
        "2"
        "1.2"
        "0.06084"
        "0.7936"
        "CVE-1234-1017"
        "3"
        "2.5"
        "0.1646"
        "0.3955"
        "CVE-1234-1018"
        "2"
        "7.5"
        "0.2059"
        "0.09260"
        "Page 3"
    )

    def setUp(self) -> None:
        self.all_product_data = [
            ProductInfo(
                product="product1",
                version="1.0",
                vendor="VendorA",
                location="/usr/local/bin/product",
            ),
            ProductInfo(
                product="product2",
                version="2.0",
                vendor="unknown",
                location="/usr/local/bin/product",
            ),
        ]
        self.output_engine = OutputEngine(
            all_cve_data=self.MOCK_OUTPUT,
            scanned_dir="",
            filename="",
            themes_dir="",
            time_of_last_update=datetime.today(),
            tag="",
        )
        self.mock_file = tempfile.NamedTemporaryFile("w+", encoding="utf-8")

    def test_generate_sbom(self):
        """Test SBOM generation"""
        with patch(
            "cve_bin_tool.sbom_manager.generate.SBOMPackage"
        ) as mock_sbom_package, patch(
            "cve_bin_tool.sbom_manager.generate.SBOMRelationship"
        ):
            mock_package_instance = MagicMock()
            mock_sbom_package.return_value = mock_package_instance

            sbomgen = SBOMGenerate(
                all_product_data=self.all_product_data,
                filename="test.sbom",
                sbom_type="spdx",
                sbom_format="tag",
                sbom_root="CVE-SCAN",
            )
            sbomgen.generate_sbom()

            # Assertions
            mock_package_instance.set_name.assert_any_call("CVEBINTOOL-CVE-SCAN")

            # Check if set_name is called for each product
            expected_calls = [
                call(product.product) for product in self.all_product_data
            ]
            mock_package_instance.set_name.assert_has_calls(
                expected_calls, any_order=True
            )

            # Check if set_version is called for each product
            expected_calls = [
                call(product.version) for product in self.all_product_data
            ]
            mock_package_instance.set_version.assert_has_calls(
                expected_calls, any_order=True
            )

            # Check if set_supplier is called for VendorA
            mock_package_instance.set_supplier.assert_any_call(
                "Organization", "VendorA"
            )

            for call_args in mock_package_instance.set_supplier.call_args_list:
                args, _ = call_args
                self.assertNotEqual(args, ("Organization", "unknown"))

            # Check if set_licensedeclared and set_licenseconcluded are called for each product
            expected_calls = [call("NOASSERTION")] * len(self.all_product_data)
            mock_package_instance.set_licensedeclared.assert_has_calls(
                expected_calls, any_order=True
            )
            mock_package_instance.set_licenseconcluded.assert_has_calls(
                expected_calls, any_order=True
            )

            # Ensure packages are added to sbom_packages correctly
            expected_packages = {
                mock_package_instance.get_package.return_value,
                mock_package_instance.get_package.return_value,
            }
            actual_packages = [package for package in sbomgen.sbom_packages.values()]
            self.assertEqual(actual_packages, list(expected_packages))

    def tearDown(self) -> None:
        self.mock_file.close()

    def test_formatted_output(self):
        """Test reformatting products"""
        self.assertEqual(
            format_output(self.MOCK_OUTPUT, None, metrics=True), self.FORMATTED_OUTPUT
        )

    def test_formatted_detailed_output(self):
        """Test detailed flag output"""
        self.assertEqual(
            format_output(self.MOCK_DETAILED_OUTPUT, None, detailed=True, metrics=True),
            self.FORMATTED_DETAILED_OUTPUT,
        )

    def test_output_json(self):
        """Test formatting output as JSON"""
        output_json(self.MOCK_OUTPUT, None, self.mock_file, metrics=True)
        self.mock_file.seek(0)  # reset file position
        self.assertEqual(json.load(self.mock_file), self.FORMATTED_OUTPUT)

    def test_output_csv(self):
        """Test formatting output as CSV"""
        output_csv(self.MOCK_OUTPUT, None, self.mock_file, metrics=True)
        self.mock_file.seek(0)  # reset file position
        reader = csv.DictReader(self.mock_file)
        actual_value = [dict(x) for x in reader]
        expected_value = [
            {
                col: v
                for col, v in row.items()
                if col not in ["response", "justification"]
            }
            for row in self.FORMATTED_OUTPUT
        ]
        self.assertEqual(actual_value, expected_value)

    @unittest.skipUnless(
        importlib.util.find_spec("reportlab") is not None
        and importlib.util.find_spec("pdftotext") is not None,
        "Skipping PDF tests. Please install reportlab and pdftotext to run these tests.",
    )
    def test_output_pdf(self):
        """Test formatting output as PDF"""
        import pdftotext

        output_pdf(
            self.MOCK_PDF_OUTPUT, False, 1, None, "cve_test.pdf", False, 0, metrics=True
        )
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

        page = pdf[2]
        section2_start = page.find("4. List of Vulnerabilities with different metric")
        self.assertEqual(
            page[section2_start:]
            .replace(" ", "")
            .replace("\r", "")
            .replace("\n", "")
            .strip(),
            self.PDF_OUTPUT_2.replace(" ", ""),
        )

    def test_output_console(self):
        """Test Formatting Output as console"""

        time_of_last_update = datetime.today()
        affected_versions = 0
        exploits = False
        metrics = True
        console = Console(file=self.mock_file)
        outfile = None
        all_product_data = None

        output_console(
            self.MOCK_OUTPUT,
            self.MOCK_ALL_CVE_VERSION_INFO,
            time_of_last_update,
            affected_versions,
            exploits,
            metrics,
            all_product_data,
            True,
            120,
            console,
            outfile,
        )

        expected_output = (
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1004 │ NVD    │ CRITICAL │ 4.2 (v2)       │ 0.00126         │ 0.46387        │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1006 │ NVD    │ LOW      │ 1.2 (v2)       │ 0.01836         │ 0.79673        │\n"
            "│ vendor0 │ product0 │ 2.8.6   │ CVE-1234-1008 │ NVD    │ UNKNOWN  │ 2.5 (v3)       │ 0.03895         │ 0.37350        │\n"
            "│ vendor0 │ product0 │ 2.8.6   │ CVE-1234-1009 │ NVD    │ MEDIUM   │ 2.5 (v3)       │ 0.03895         │ 0.37350        │\n"
            "│ vendor1 │ product1 │ 3.2.1.0 │ CVE-1234-1010 │ OSV    │ HIGH     │ 7.5 (v2)       │ 0.0468          │ 0.34072        │\n"
            "└─────────┴──────────┴─────────┴───────────────┴────────┴──────────┴────────────────┴─────────────────┴────────────────┘\n"
        )
        expected_output_2 = (
            "│ CVE-1234-1004 │ 2            │ 4.2        │ 0.00126          │ 0.46387         │\n"
            "│ CVE-1234-1006 │ 2            │ 1.2        │ 0.01836          │ 0.79673         │\n"
            "│ CVE-1234-1008 │ 3            │ 2.5        │ 0.03895          │ 0.37350         │\n"
            "│ CVE-1234-1009 │ 3            │ 2.5        │ 0.03895          │ 0.37350         │\n"
            "│ CVE-1234-1010 │ 2            │ 7.5        │ 0.0468           │ 0.34072         │\n"
            "│ CVE-1234-1007 │ 3            │ 2.5        │ 0.03895          │ 0.37350         │\n"
            "│ CVE-1234-1005 │ 2            │ 4.2        │ 0.00126          │ 0.46387         │\n"
            "└───────────────┴──────────────┴────────────┴──────────────────┴─────────────────┘\n"
        )

        self.mock_file.seek(0)  # reset file position
        result = self.mock_file.read()
        self.assertIn(expected_output, result)
        self.assertIn(expected_output_2, result)

    def test_output_console_affected_versions(self):
        """Test Formatting Output as console with affected-versions"""

        time_of_last_update = datetime.today()
        affected_versions = 1
        exploits = False
        metrics = True
        console = Console(file=self.mock_file)
        outfile = None
        all_product_data = None

        output_console(
            self.MOCK_ALL_CVE_DATA,
            self.MOCK_ALL_CVE_VERSION_INFO,
            time_of_last_update,
            affected_versions,
            exploits,
            metrics,
            all_product_data,
            True,
            120,
            console,
            outfile,
        )

        expected_output = (
            "│ vendor0 │ product0 │ 1.0     │ UNKNOWN     │ NVD    │ UNKNOWN  │ 0 (v0)      │ -          │ -           │ -          │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.299      │ 0.25934     │ [0.9.0 -   │\n"
            "│         │          │         │             │        │          │             │            │             │ 1.2.0]     │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.0285     │ 0.94667     │ [0.9.0 -   │\n"
            "│         │          │         │             │        │          │             │            │             │ 1.2.0)     │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.0468     │ 0.34072     │ (0.9.0 -   │\n"
            "│         │          │         │             │        │          │             │            │             │ 1.2.0]     │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.35337    │ 0.72282     │ (0.9.0 -   │\n"
            "│         │          │         │             │        │          │             │            │             │ 1.2.0)     │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.1537     │ 0.21433     │ >= 0.9.0   │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.0513     │ 0.77186     │ > 0.9.0    │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.0836     │ 0.53389     │ <= 1.2.0   │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-0… │ NVD    │ MEDIUM   │ 4.2 (v2)    │ 0.36957    │ 0.83771     │ < 1.2.0    │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-9999-9… │ NVD    │ LOW      │ 1.2 (v2)    │ 0.01296    │ 0.67261     │ -          │\n"
            "└─────────┴──────────┴─────────┴─────────────┴────────┴──────────┴─────────────┴────────────┴─────────────┴────────────┘\n"
        )

        self.mock_file.seek(0)  # reset file position
        result = self.mock_file.read()
        print(result)
        self.assertIn(expected_output, result)

    def test_output_console_outfile(self):
        """Test output to a file"""

        tmpf = tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8")
        tmpf.close()  # accessing open tempfile on windows gives error

        time_of_last_update = datetime.today()
        affected_versions = 0
        exploits = False
        metrics = True
        outfile = tmpf.name
        all_product_data = None

        output_console(
            self.MOCK_OUTPUT,
            self.MOCK_ALL_CVE_VERSION_INFO,
            time_of_last_update,
            affected_versions,
            exploits,
            metrics,
            all_product_data,
            True,
            120,
            outfile,
        )

        expected_output = (
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1004 │ NVD    │ CRITICAL │ 4.2 (v2)       │ 0.00126         │ 0.46387        │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1006 │ NVD    │ LOW      │ 1.2 (v2)       │ 0.01836         │ 0.79673        │\n"
            "│ vendor0 │ product0 │ 2.8.6   │ CVE-1234-1008 │ NVD    │ UNKNOWN  │ 2.5 (v3)       │ 0.03895         │ 0.37350        │\n"
            "│ vendor0 │ product0 │ 2.8.6   │ CVE-1234-1009 │ NVD    │ MEDIUM   │ 2.5 (v3)       │ 0.03895         │ 0.37350        │\n"
            "│ vendor1 │ product1 │ 3.2.1.0 │ CVE-1234-1010 │ OSV    │ HIGH     │ 7.5 (v2)       │ 0.0468          │ 0.34072        │\n"
            "└─────────┴──────────┴─────────┴───────────────┴────────┴──────────┴────────────────┴─────────────────┴────────────────┘\n"
        )
        expected_output_2 = (
            "│ CVE-1234-1004 │ 2            │ 4.2        │ 0.00126          │ 0.46387         │\n"
            "│ CVE-1234-1006 │ 2            │ 1.2        │ 0.01836          │ 0.79673         │\n"
            "│ CVE-1234-1008 │ 3            │ 2.5        │ 0.03895          │ 0.37350         │\n"
            "│ CVE-1234-1009 │ 3            │ 2.5        │ 0.03895          │ 0.37350         │\n"
            "│ CVE-1234-1010 │ 2            │ 7.5        │ 0.0468           │ 0.34072         │\n"
            "│ CVE-1234-1007 │ 3            │ 2.5        │ 0.03895          │ 0.37350         │\n"
            "│ CVE-1234-1005 │ 2            │ 4.2        │ 0.00126          │ 0.46387         │\n"
            "└───────────────┴──────────────┴────────────┴──────────────────┴─────────────────┘\n"
        )

        with open(tmpf.name, encoding="utf-8") as f:
            result = f.read()
        self.assertIn(expected_output, result)
        self.assertIn(expected_output_2, result)
        Path(tmpf.name).unlink()  # deleting tempfile

    def test_output_console_metrics_false(self):
        """Test Formatting Output as console with metrics=False"""

        time_of_last_update = datetime.today()
        affected_versions = 0
        exploits = False
        metrics = False
        console = Console(file=self.mock_file)
        outfile = None
        all_product_data = None

        output_console(
            self.MOCK_OUTPUT_2,
            self.MOCK_ALL_CVE_VERSION_INFO,
            time_of_last_update,
            affected_versions,
            exploits,
            metrics,
            all_product_data,
            True,
            120,
            console,
            outfile,
        )

        expected_output = (
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1011 │ NVD    │ LOW      │ 6.4 (v2)             │\n"
            "│ vendor0 │ product0 │ 1.0     │ CVE-1234-1012 │ NVD    │ MEDIUM   │ 1.2 (v2)             │\n"
            "│ vendor0 │ product0 │ 2.8.7   │ CVE-1234-1013 │ NVD    │ LOW      │ 2.5 (v3)             │\n"
            "│ vendor1 │ product1 │ 3.3.1   │ CVE-1234-1014 │ OSV    │ HIGH     │ 7.5 (v2)             │\n"
            "└─────────┴──────────┴─────────┴───────────────┴────────┴──────────┴──────────────────────┘\n"
        )

        self.mock_file.seek(0)
        result = self.mock_file.read()
        self.assertIn(expected_output, result)
        # Assert that the metrics table is not output
        expected_output = (
            "┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓\n"
            "┃ CVE           ┃ CVSS_version ┃ CVSS_score ┃ EPSS_probability ┃ EPSS_percentile ┃\n"
            "┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩\n"
        )
        self.assertNotIn(expected_output, result)

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
            ProductInfo(
                "=vendor0", "\t+product0", "@1.0", "/usr/local/bin/product"
            ): CVEData(
                cves=[
                    CVE(
                        "-CVE-1234-1234",
                        "\t\r@-=+MEDIUM",
                        score=4.2,
                        cvss_version=2,
                        cvss_vector="\rC:H",
                        data_source="NVD",
                        metric={
                            "EPSS": [0.00126, "0.46387"],
                        },
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
                "location": "/usr/local/bin/product",
                "cve_number": "CVE-1234-1234",
                "source": "NVD",
                "severity": "MEDIUM",
                "score": "4.2",
                "cvss_version": "2",
                "cvss_vector": "C:H",
                "epss_probability": "0.00126",
                "epss_percentile": "0.46387",
                "paths": "bad",
                "remarks": "NewFound",
                "comments": "",
            },
        ]

        output_csv(bad_input, None, self.mock_file, metrics=True)
        self.mock_file.seek(0)  # reset file position
        reader = csv.DictReader(self.mock_file)
        actual_output = [dict(x) for x in reader]
        self.assertEqual(actual_output, expected_output)
