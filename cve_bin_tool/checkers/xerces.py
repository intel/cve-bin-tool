# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libxerces

References:
https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&orderBy=2.3&keyword=cpe%3A2.3%3Aa%3Aapache%3Axerces-c%5C%2B%5C%2B&status=FINAL

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=45&product_id=4103&version_id=&orderby=2&cvssscoremin=0
"""
from cve_bin_tool.checkers import Checker


class XercesChecker(Checker):
    CONTAINS_PATTERNS = [r"xerces-c-src_"]
    FILENAME_PATTERNS = [r"libxerces-c.so", r"libxerces-c-3.1.so"]
    VERSION_PATTERNS = [
        r"\/xerces-c-src_([0-9]+_[0-9]+_[0-9]+)\/",
        r"xercesc_([0-9]+\_[0-9]+):",
    ]
    VENDOR_PRODUCT = [("apache", "xerces-c\\+\\+")]
