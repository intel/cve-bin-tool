#!/usr/bin/python3

"""
CVE checker for openldap

https://www.cvedetails.com/product/755/Openldap-Openldap.html?vendor_id=439

"""
from . import Checker


class OpenldapChecker(Checker):
    FILENAME_PATTERNS = [r"ldapsearch"]
    VERSION_PATTERNS = [r"ldapsearch ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openldap", "openldap")]
