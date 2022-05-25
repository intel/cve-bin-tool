# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for varnish
https://www.cvedetails.com/vulnerability-list/vendor_id-12937/product_id-26407/Varnish-cache-Varnish.html
"""
from cve_bin_tool.checkers import Checker


class VarnishChecker(Checker):
    CONTAINS_PATTERNS = [
        r"\(pthread_create\(&v->tp, \(\(void \*\)0\), varnish_thread, v\)\) == 0",
        r"\(pthread_create\(&v->tp_vsl, \(\(void \*\)0\), varnishlog_thread, v\)\) == 0",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"Clients that do not support gzip will have their Accept-Encoding header removed\. For more information on how gzip is implemented please see the chapter on gzip in the Varnish reference\.",
    ]
    FILENAME_PATTERNS = [r"varnish"]
    VERSION_PATTERNS = [r"varnish-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("varnish-cache", "varnish")]
