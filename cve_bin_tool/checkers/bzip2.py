#!/usr/bin/python3

"""
CVE checker for bzip2

https://www.cvedetails.com/vulnerability-list/vendor_id-1198/product_id-2068/Bzip-Bzip2.html

"""
from . import Checker


class Bzip2Checker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"bzip2"]
    VERSION_PATTERNS = [r"bzip2-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("bzip", "bzip2")]
