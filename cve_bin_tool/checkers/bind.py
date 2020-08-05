#!/usr/bin/python3

"""
CVE checker for bind

https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64

"""
from . import Checker


class BindChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"named"]
    VERSION_PATTERNS = [r"BIND ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("isc", "bind")]
