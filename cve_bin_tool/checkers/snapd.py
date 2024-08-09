# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for snapd

https://www.cvedetails.com/vulnerability-list/vendor_id-4781/product_id-56931/Canonical-Snapd.html
https://www.cvedetails.com/product/65481/Snapcraft-Snapd.html?vendor_id=21528

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SnapdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = [
        r"# Allow use of snapd's internal 'xdg-open'",
        r"# Allow use of snapd's internal 'xdg-settings'",
        r"# Description: Can manage snaps via snapd.",
    ]
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"snapd-([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("canonical", "snapd"), ("snapcraft", "snapd")]
