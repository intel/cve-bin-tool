#!/usr/bin/python3

"""
CVE checker for nessus

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-12865/product_id-27428/Tenable-Nessus.html
"""
from . import Checker


class NessusChecker(Checker):
    CONTAINS_PATTERNS = [
        r"you have deleted older versions nessus libraries from your system",
        r"server_info_nessusd_version",
        r"nessuslib_version",
        r"nessus_lib_version",
    ]
    FILENAME_PATTERNS = [r"libnessus"]
    VERSION_PATTERNS = [
        r"Nessus ([0-9]+\.[0-9]+\.[0-9]+)",
        r"libnessus.so.([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("tenable", "nessus")]
