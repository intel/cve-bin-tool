# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for librsvg

https://www.cvedetails.com/vulnerability-list/vendor_id-283/product_id-23082/Gnome-Librsvg.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibrsvgChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"librsvg"]
    VERSION_PATTERNS = [r"librsvg[0-9]?-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnome", "librsvg")]
