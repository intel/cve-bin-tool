#!/usr/bin/python3

"""
CVE checker for wireshark

https://www.cvedetails.com/product/8292/Wireshark-Wireshark.html?vendor_id=4861

"""
from . import Checker


class WiresharkChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"rawshark"]
    VERSION_PATTERNS = [r"Wireshark ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("wireshark", "wireshark")]
