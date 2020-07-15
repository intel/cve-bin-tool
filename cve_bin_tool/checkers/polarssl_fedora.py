#!/usr/bin/python3

"""
CVE checker for polarssl

This checker currently works on only fedora distribution, because of lack of common signatures
in other distributions, with unsuccessful attempts made for CentOS and ubuntu distributions.

https://www.cvedetails.com/product/22470/Polarssl-Polarssl.html?vendor_id=12001

"""
from . import Checker


class PolarsslFedoraChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"libpolarssl.so."]
    VERSION_PATTERNS = [r"libpolarssl.so.([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("polarssl", "polarssl")]
