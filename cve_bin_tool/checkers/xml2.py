# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libxml2

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-1962/product_id-3311/Xmlsoft-Libxml2.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=1962&product_id=3311&version_id=&orderby=2&cvssscoremin=0
"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Xml2Checker(Checker):
    CONTAINS_PATTERNS = [
        r"Internal error, xmlCopyCharMultiByte 0x%X out of bound",
        r"xmlNewElementContent : name != NULL !",
        r"xmlRelaxNG: include %s has a define %s but not the included grammar",
    ]
    FILENAME_PATTERNS = [r"libxml2.so."]
    VERSION_PATTERNS: list[str] = [
        r"libxml2-([0-9]+\.[0-9]+\.[0-9]+)",
        r"libxml2.so.([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("xmlsoft", "libxml2")]
