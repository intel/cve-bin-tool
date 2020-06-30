#!/usr/bin/python3

"""
CVE checker for zlib
--------
References:
http://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-1820/GNU-Zlib.html
https://zlib.net/ChangeLog.txt

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=72&product_id=1820&version_id=&orderby=2&cvssscoremin=0
"""
from . import Checker
from string import printable


class ZlibChecker(Checker):
    CONTAINS_PATTERNS = [
        rf"deflate[{printable}]*Copyright 1995-2005 Jean-loup Gailly",
        rf"Copyright 1995-2005 Mark Adler[{printable}]*inflate",
        r"too many length or distance symbols",
    ]
    FILENAME_PATTERNS = [r"libz.so."]
    VERSION_PATTERNS = [
        r"deflate ([01]+\.[0-9]+\.[0-9]+) ",
        r"inflate ([01]+\.[0-9]+\.[0-9]+) ",
    ]
    VENDOR_PRODUCT = [("gnu", "zlib")]
