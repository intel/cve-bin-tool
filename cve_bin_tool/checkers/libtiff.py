#!/usr/bin/python3

"""
CVE checker for libtiff

http://www.cvedetails.com/vulnerability-list/vendor_id-2224/product_id-3881/Libtiff-Libtiff.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=2224&product_id=3881&version_id=&orderby=3&cvssscoremin=0
"""
from . import Checker


class LibtiffChecker(Checker):
    CONTAINS_PATTERNS = [
        r"LIBTIFF, Version ",
        r"Unknown TIFF resolution unit %d ignored",
        r'TIFF directory is missing required "StripByteCounts" field, calculating from imagelength',
    ]
    FILENAME_PATTERNS = [r"libtiff.so."]
    VERSION_PATTERNS = [r"LIBTIFF, Version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libtiff", "libtiff")]
