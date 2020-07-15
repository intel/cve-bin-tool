#!/usr/bin/python3

"""
CVE checker for freeradius

https://www.cvedetails.com/product/1805/Freeradius-Freeradius.html?vendor_id=1039

"""
from . import Checker


class FreeradiusChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"radiusd"]
    VERSION_PATTERNS = [r"FreeRADIUS Version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("freeradius", "freeradius")]
