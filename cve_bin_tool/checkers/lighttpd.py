#!/usr/bin/python3

"""
CVE checker for lighttpd

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-2713/product_id-4762/Lighttpd-Lighttpd.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=2713&product_id=4762&version_id=0&orderby=3&cvssscoremin=0

"""
from . import Checker


class LighttpdChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Invalid fds at startup with lighttpd",
        r"lighttpd will fail to start up",
    ]
    FILENAME_PATTERNS = [r"lighttpd"]
    VERSION_PATTERNS = [r"lighttpd/([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("lighttpd", "lighttpd")]
