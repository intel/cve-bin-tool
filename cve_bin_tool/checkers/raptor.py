# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for raptor

https://www.cvedetails.com/product/66685/Librdf-Raptor-Rdf-Syntax-Library.html?vendor_id=21628

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RaptorChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"\r?\nrapper-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nhttp://librdf.org/raptor",
    ]
    VENDOR_PRODUCT = [("librdf", "raptor_rdf_syntax_library")]
