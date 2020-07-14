#!/usr/bin/python3

"""
CVE checker for icecast

https://www.cvedetails.com/product/1194/Icecast-Icecast.html?vendor_id=693

"""
from . import Checker


class IcecastChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"icecast"]
    VERSION_PATTERNS = [r"Icecast ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("icecast", "icecast")]
