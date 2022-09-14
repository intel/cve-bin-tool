# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from test.utils import LONG_TESTS

import pytest
from pytest_mock import MockerFixture

from cve_bin_tool.available_fix import AvailableFixReport
from cve_bin_tool.available_fix.debian_cve_tracker import check_json
from cve_bin_tool.util import CVE, CVEData, ProductInfo


class TestAvailableFixReport:
    @pytest.fixture(autouse=True)
    def arrange_data(self):
        check_json()

    @pytest.mark.skipif(
        LONG_TESTS() != 1, reason="Skipping tests to reduce network calls"
    )
    def test_long_debian_backport_fix_output(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test Backported fix for Debian distros output on console with external API"""

        fixes = AvailableFixReport(self.MOCK_PSPP_CVE_DATA, "debian-bullseye", True)
        fixes.check_available_fix()
        expected_output = [
            "pspp: CVE-2018-20230 has backported fix in v1.2.0-3 release.",
            "pspp: CVE-2019-9211 has backported fix in v1.2.0-4 release.",
        ]

        assert expected_output == [rec.message for rec in caplog.records]

    def test_debian_backport_fix_output(
        self, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test Backported fix for Debian distros output on console"""

        fixes = AvailableFixReport(self.MOCK_PSPP_CVE_DATA, "debian-bullseye", True)
        mocker.patch(
            "cve_bin_tool.available_fix.debian_cve_tracker.DebianCVETracker.get_data",
            return_value=self.MOCK_DEBIAN_API,
        )
        fixes.check_available_fix()
        expected_output = [
            "pspp: CVE-2018-20230 has backported fix in v1.2.0-3 release.",
            "pspp: CVE-2019-9211 has backported fix in v1.2.0-4 release.",
        ]

        assert expected_output == [rec.message for rec in caplog.records]

    @pytest.mark.skipif(
        LONG_TESTS() != 1, reason="Skipping tests to reduce network calls"
    )
    def test_long_debian_available_fix_output(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test Available fix for Debian distros output on console with external API"""

        fixes = AvailableFixReport(self.MOCK_AVAHI_CVE_DATA, "debian-bullseye", False)
        fixes.check_available_fix()
        expected_output = [
            "avahi: CVE-2010-2244 has available fix in v0.6.26-1 release.",
            "avahi: CVE-2011-1002 has available fix in v0.6.28-4 release.",
            "avahi: CVE-2017-6519 has available fix in v0.7-5 release.",
            "avahi: CVE-2021-26720 has available fix in v0.8-4 release.",
        ]

        assert expected_output == [rec.message for rec in caplog.records]

    def test_debian_available_fix_output(
        self, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test Available fix for Debian distros output on console"""

        fixes = AvailableFixReport(self.MOCK_AVAHI_CVE_DATA, "debian-bullseye", False)
        mocker.patch(
            "cve_bin_tool.available_fix.debian_cve_tracker.DebianCVETracker.get_data",
            return_value=self.MOCK_DEBIAN_API,
        )
        fixes.check_available_fix()
        expected_output = [
            "avahi: CVE-2010-2244 has available fix in v0.6.26-1 release.",
            "avahi: CVE-2011-1002 has available fix in v0.6.28-4 release.",
            "avahi: CVE-2017-6519 has available fix in v0.7-5 release.",
            "avahi: CVE-2021-26720 has available fix in v0.8-4 release.",
        ]

        assert expected_output == [rec.message for rec in caplog.records]

    @pytest.mark.skipif(
        LONG_TESTS() != 1, reason="Skipping tests to reduce network calls"
    )
    def test_long_redhat_available_fix_output(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test Available fix for Redhat distros output on console with external API"""

        fixes = AvailableFixReport(self.MOCK_NODEJS_CVE_DATA, "rhel-8", False)
        fixes.check_available_fix()
        expected_output = [
            "node.js: CVE-2021-22918 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22918 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22918 - Status: Fixed - Fixed package: libuv v1.41",
            "node.js: CVE-2021-22918 - Status: Not affected - Related package: nodejs v16",
            "node.js: CVE-2021-22931 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22931 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22931 - Status: Not affected - Related package: nodejs v16",
            "node.js: CVE-2021-22939 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22939 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22939 - Status: Not affected - Related package: nodejs v16",
            "node.js: CVE-2021-22940 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22940 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22940 - Status: Not affected - Related package: nodejs v16",
        ]

        assert expected_output == [rec.message for rec in caplog.records]

    def test_redhat_available_fix_output(
        self, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test Available fix for Redhat distros output on console"""

        fixes = AvailableFixReport(self.MOCK_NODEJS_CVE_DATA, "rhel-8", False)
        mocker.patch(
            "cve_bin_tool.available_fix.redhat_cve_tracker.RedhatCVETracker.get_data",
            return_value=self.MOCK_RH_API,
        )
        fixes.check_available_fix()
        expected_output = [
            "node.js: CVE-2021-22918 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22918 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22918 - Status: Fixed - Fixed package: libuv v1.41",
            "node.js: CVE-2021-22918 - Status: Not affected - Related package: nodejs v16",
            "node.js: CVE-2021-22931 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22931 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22931 - Status: Fixed - Fixed package: libuv v1.41",
            "node.js: CVE-2021-22931 - Status: Not affected - Related package: nodejs v16",
            "node.js: CVE-2021-22939 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22939 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22939 - Status: Fixed - Fixed package: libuv v1.41",
            "node.js: CVE-2021-22939 - Status: Not affected - Related package: nodejs v16",
            "node.js: CVE-2021-22940 - Status: Fixed - Fixed package: nodejs v12",
            "node.js: CVE-2021-22940 - Status: Fixed - Fixed package: nodejs v14",
            "node.js: CVE-2021-22940 - Status: Fixed - Fixed package: libuv v1.41",
            "node.js: CVE-2021-22940 - Status: Not affected - Related package: nodejs v16",
        ]

        assert expected_output == [rec.message for rec in caplog.records]

    MOCK_PSPP_CVE_DATA = {
        ProductInfo(vendor="gnu", product="pspp", version="1.2.0"): CVEData(
            None,
            {
                "cves": [
                    CVE(
                        cve_number="CVE-2018-20230",
                        severity="HIGH",
                    ),
                    CVE(
                        cve_number="CVE-2019-9211",
                        severity="MEDIUM",
                    ),
                ],
            },
        )
    }

    MOCK_AVAHI_CVE_DATA = {
        ProductInfo(vendor="avahi", product="avahi", version="0.6.25"): CVEData(
            None,
            {
                "cves": [
                    CVE(
                        cve_number="CVE-2010-2244",
                        severity="MEDIUM",
                    ),
                    CVE(
                        cve_number="CVE-2011-1002",
                        severity="MEDIUM",
                    ),
                    CVE(
                        cve_number="CVE-2017-6519",
                        severity="CRITICAL",
                    ),
                    CVE(
                        cve_number="CVE-2021-26720",
                        severity="HIGH",
                    ),
                    CVE(
                        cve_number="CVE-2021-3468",
                        severity="MEDIUM",
                    ),
                ],
            },
        )
    }

    MOCK_NODEJS_CVE_DATA = {
        ProductInfo(vendor="nodejs", product="node.js", version="14.16.0"): CVEData(
            None,
            {
                "cves": [
                    CVE(
                        cve_number="CVE-2021-22918",
                        severity="MEDIUM",
                    ),
                    CVE(
                        cve_number="CVE-2021-22931",
                        severity="CRITICAL",
                    ),
                    CVE(
                        cve_number="CVE-2021-22939",
                        severity="MEDIUM",
                    ),
                    CVE(
                        cve_number="CVE-2021-22940",
                        severity="HIGH",
                    ),
                ],
            },
        )
    }

    MOCK_RH_API = {
        "affected_release": [
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "package": "nodejs:12-8040020210708131418.522a0ee4",
            },
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "package": "nodejs:14-8040020210708154809.522a0ee4",
            },
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "package": "libuv-1:1.41.1-1.el8_4",
            },
        ],
        "package_state": [
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "fix_state": "Not affected",
                "package_name": "nodejs:16/nodejs",
            }
        ],
    }

    MOCK_DEBIAN_API = {
        "pspp": {
            "CVE-2018-20230": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "fixed_version": "1.2.0-3",
                    },
                },
            },
            "CVE-2019-9211": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "fixed_version": "1.2.0-4",
                    },
                },
            },
        },
        "avahi": {
            "CVE-2010-2244": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "fixed_version": "0.6.26-1",
                    },
                },
            },
            "CVE-2011-1002": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "fixed_version": "0.6.28-4",
                    },
                },
            },
            "CVE-2017-6519": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "fixed_version": "0.7-5",
                    },
                },
            },
            "CVE-2021-26720": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "fixed_version": "0.8-4",
                    },
                },
            },
            "CVE-2021-3468": {
                "releases": {
                    "bullseye": {
                        "status": "open",
                    },
                }
            },
        },
    }
