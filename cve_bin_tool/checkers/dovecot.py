#!/usr/bin/python3

"""
CVE checker for dovecot

https://www.cvedetails.com/product/10948/Dovecot-Dovecot.html?vendor_id=6485

"""
from . import Checker


class DovecotChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"dovecot"]
    VERSION_PATTERNS = [r"Dovecot v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("dovecot", "dovecot")]
