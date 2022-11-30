# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libjpeg

https://www.cvedetails.com/product/46165/IJG-Libjpeg.html?vendor_id=17990

"""
from cve_bin_tool.checkers import Checker


class LibjpegChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = []
    VERSION_PATTERNS = [r"\n([0-9][a-z])  [0-9]+-[a-zA-Z]+-[0-9]+"]
    VENDOR_PRODUCT = [("ijg", "libjpeg")]
