# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libcurl

References:
https://curl.haxx.se/docs/security.html
http://www.cvedetails.com/vulnerability-list/vendor_id-12682/Haxx.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12682&product_id=0&version_id=0&orderby=3&cvssscoremin=0

Note: Some of the "first vulnerable in" data may not be entered correctly.
"""
from cve_bin_tool.checkers import Checker


class LibcurlChecker(Checker):
    CONTAINS_PATTERNS = [
        r"An unknown option was passed in to libcurl",
        r"A requested feature, protocol or option was not found built-in in this libcurl due to a build-time decision.",
        r"CLIENT libcurl 7.",
    ]
    FILENAME_PATTERNS = [r"libcurl.so."]
    VERSION_PATTERNS = [r"CLIENT libcurl ([678]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("haxx", "curl"), ("haxx", "libcurl")]
