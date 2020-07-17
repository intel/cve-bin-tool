#!/usr/bin/python3

"""
CVE checker for openafs

https://www.cvedetails.com/product/2873/Openafs-Openafs.html?vendor_id=1664

"""
from . import Checker


class OpenafsChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"afsd"]
    VERSION_PATTERNS = [r"OpenAFS ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openafs", "openafs")]
