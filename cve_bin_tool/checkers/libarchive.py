#!/usr/bin/python3

"""
CVE checker for libarchive

https://www.cvedetails.com/product/26168/Libarchive-Libarchive.html?vendor_id=12872

"""
from . import Checker


class LibarchiveChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"libarchive.so"]
    VERSION_PATTERNS = [r"libarchive ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libarchive", "libarchive")]
