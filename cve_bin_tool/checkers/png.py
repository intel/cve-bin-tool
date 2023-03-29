# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libpng

References:
https://www.cvedetails.com/product/3774/Redhat-Libpng.html?vendor_id=25
https://www.cvedetails.com/product/2056/Greg-Roelofs-Libpng.html?vendor_id=1189
http://www.cvedetails.com/vulnerability-list/vendor_id-7294/Libpng.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=7294&product_id=0&version_id=&orderby=3&cvssscoremin=0
"""
from cve_bin_tool.checkers import Checker


class PngChecker(Checker):
    CONTAINS_PATTERNS = [
        r"libpng error: %s, offset=%d",
        r"Application uses deprecated png_write_init\(\) and should be recompiled",
        r"libpng version ",
    ]
    FILENAME_PATTERNS = [r"libpng.so.", r"libpng16.so."]
    VERSION_PATTERNS = [r"libpng version ([0-9]+\.[0-9]+\.[0-9]+) -"]
    VENDOR_PRODUCT = [
        ("greg_roelofs", "libpng"),
        ("libpng", "libpng"),
        ("redhat", "libpng"),
    ]
