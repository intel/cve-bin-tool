# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for poppler

https://www.cvedetails.com/product/6675/?q=Poppler
https://www.cvedetails.com/vulnerability-list/vendor_id-7971/product_id-24992/Freedesktop-Poppler.html

"""
from cve_bin_tool.checkers import Checker


class PopplerChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Unknown CID font collection, please report to poppler bugzilla."
    ]
    FILENAME_PATTERNS = [r"libpoppler.so"]
    VERSION_PATTERNS = [r"poppler-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("poppler", "poppler"), ("freedesktop", "poppler")]
