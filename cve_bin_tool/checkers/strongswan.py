#!/usr/bin/python3

"""
CVE checker for strongswan

https://www.cvedetails.com/product/3992/Strongswan-Strongswan.html?vendor_id=2278

"""
from . import Checker


class StrongswanChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"libcharon.so"]
    VERSION_PATTERNS = [r"strongSwan ([0-9]+\.[0-9]+\.[0-9])"]
    VENDOR_PRODUCT = [("strongswan", "strongswan")]
