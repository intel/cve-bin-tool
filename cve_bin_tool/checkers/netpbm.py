#!/usr/bin/python3

"""
CVE checker for netpbm

https://www.cvedetails.com/product/2877/Netpbm-Netpbm.html?vendor_id=1666

"""
from . import Checker


class NetpbmChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"libnetpbm.so"]
    VERSION_PATTERNS = [r"Netpbm ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("netpbm", "netpbm")]
