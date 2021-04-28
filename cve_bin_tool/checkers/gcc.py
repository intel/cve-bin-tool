# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gcc

https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-960/GNU-GCC.html

"""
from cve_bin_tool.checkers import Checker


class GccChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTTERN = [r"gcc"]
    VERSION_PATTERNS = [
        r"gcc ([0-9]+\.[0-9]+\.[0-9]+)",
        r"gcc ([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "gcc"), ("gcc", "gcc")]
