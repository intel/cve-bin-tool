#!/usr/bin/python3

"""
CVE checker for avahi

https://www.cvedetails.com/product/7747/Avahi-Avahi.html?vendor_id=4481

"""
from . import Checker


class AvahiChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"avahi-daemon"]
    VERSION_PATTERNS = [r"avahi ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("avahi", "avahi")]
