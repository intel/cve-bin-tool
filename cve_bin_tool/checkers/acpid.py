# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for acpid

https://www.cvedetails.com/product/17268/Tim-Hockin-Acpid.html?vendor_id=9660
https://www.cvedetails.com/product/21292/Tedfelix-Acpid.html?vendor_id=11569
https://www.cvedetails.com/product/23004/Tedfelix-Acpid2.html?vendor_id=11569

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AcpidChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["acpid\\-([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("tedfelix", "acpid"),
        ("tedfelix", "acpid2"),
        ("tim_hockin", "acpid"),
    ]
