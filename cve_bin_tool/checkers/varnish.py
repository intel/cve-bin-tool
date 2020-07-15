#!/usr/bin/python3

"""
CVE checker for varnish
https://www.cvedetails.com/vulnerability-list/vendor_id-12937/product_id-26407/Varnish-cache-Varnish.html
"""
from . import Checker


class VarnishChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"varnish"]
    VERSION_PATTERNS = [r"varnish-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("varnish-cache", "varnish")]
