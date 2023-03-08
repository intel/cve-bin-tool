# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for asn1c

https://www.cvedetails.com/product/39543/Asn1c-Project-Asn1c.html?vendor_id=16848

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Asn1CChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = ["asn1c"]
    VERSION_PATTERNS = [r"asn1c-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("asn1c_project", "asn1c")]
