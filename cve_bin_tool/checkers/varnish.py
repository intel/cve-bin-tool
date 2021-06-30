# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for varnish
https://www.cvedetails.com/vulnerability-list/vendor_id-12937/product_id-26407/Varnish-cache-Varnish.html
"""
from cve_bin_tool.checkers import Checker


class VarnishChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"varnish"]
    VERSION_PATTERNS = [r"varnish-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("varnish-cache", "varnish")]
