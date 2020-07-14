#!/usr/bin/python3

"""
CVE checker for haproxy

https://www.cvedetails.com/product/22372/Haproxy-Haproxy.html?vendor_id=11969

"""
from . import Checker


class HaproxyChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"haproxy"]
    VERSION_PATTERNS = [r"HA-Proxy version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("haproxy", "haproxy")]
