#!/usr/bin/python3

"""
CVE checker for hostapd

https://www.cvedetails.com/product/22495/W1.fi-Hostapd.html?vendor_id=12005

"""
from . import Checker


class HostapdChecker(Checker):
    # FIXME: fix contains pattern
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"hostapd"]
    VERSION_PATTERNS = [r"hostapd v([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("w1.fi", "hostapd")]
