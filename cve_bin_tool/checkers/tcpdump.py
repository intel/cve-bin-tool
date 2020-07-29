#!/usr/bin/python3

"""
CVE checker for tcpdump

https://www.cvedetails.com/product/10494/Tcpdump-Tcpdump.html?vendor_id=6197

"""
from . import Checker


class TcpdumpChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"tcpdump"]
    VERSION_PATTERNS = [r"tcpdump-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("tcpdump", "tcpdump")]
