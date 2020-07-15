#!/usr/bin/python3

"""
CVE checker for gimp

https://www.cvedetails.com/product/17152/Gimp-Gimp.html?vendor_id=9605

"""
from . import Checker


class GimpChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"gimp"]
    VERSION_PATTERNS = [r"GIMP ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gimp", "gimp")]
