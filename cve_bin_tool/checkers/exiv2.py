# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for exiv2

https://www.cvedetails.com/product/6748/Andreas-Huggel-Exiv2.html?vendor_id=3849
https://www.cvedetails.com/product/12768/Exiv2-Exiv2.html?vendor_id=7561

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Exiv2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"exiv2 ([0-9]+\.[0-9]+\.?[0-9]*)"]
    VENDOR_PRODUCT = [("andreas_huggel", "exiv2"), ("exiv2", "exiv2")]
