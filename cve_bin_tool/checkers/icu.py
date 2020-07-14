#!/usr/bin/python3

"""
CVE checker for icu CLI

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-17477/Icu-project.html
"""
from . import Checker


class IcuChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"icu", r"international_components_for_unicode"]
    VERSION_PATTERNS = [
        r"icu[_-]([0-9]+\.[0-9]+\.[0-9]+)",
        r"ICU ([0-9]+\.[0-9]+\.[0-9]+)",
        r"icu[_-][relas-]*((0*(?:[1-6][0-9]?))+(\-[0-9]+)*)",
    ]
    VENDOR_PRODUCT = [("icu-project", "international_components_for_unicode")]
