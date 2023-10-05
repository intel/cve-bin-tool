# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for qpdf

https://www.cvedetails.com/product/38012/Qpdf-Project-Qpdf.html?vendor_id=16505

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class QpdfChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"QPDF decoding error warning\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"qpdf-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("qpdf_project", "qpdf")]
