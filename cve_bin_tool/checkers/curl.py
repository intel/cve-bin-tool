#!/usr/bin/python3

"""
CVE checker for curl CLI

References:
https://curl.haxx.se/docs/security.html
http://www.cvedetails.com/vulnerability-list/vendor_id-12682/Haxx.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12682&product_id=0&version_id=0&orderby=3&cvssscoremin=0

Note: Some of the "first vulnerable in" data may not be entered correctly.
"""
from . import Checker


class CurlChecker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"curl"]
    VERSION_PATTERNS = [r"curl ([678]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("haxx", "curl")]
