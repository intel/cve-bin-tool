# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for curl CLI

References:
https://curl.haxx.se/docs/security.html
http://www.cvedetails.com/vulnerability-list/vendor_id-12682/Haxx.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12682&product_id=0&version_id=0&orderby=3&cvssscoremin=0

Note: Some of the "first vulnerable in" data may not be entered correctly.
"""
from cve_bin_tool.checkers import Checker


class CurlChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Dump libcurl equivalent code of this command line",
        r"a specified protocol is unsupported by libcurl",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"curl failed to verify the legitimacy of the server and therefore could not",
        # r"error retrieving curl library information",
        # r"ignoring --proxy-capath, not supported by libcurl",
    ]
    FILENAME_PATTERNS = [r"curl"]
    VERSION_PATTERNS = [r"\r?\ncurl[ -/]([678]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("haxx", "curl")]
