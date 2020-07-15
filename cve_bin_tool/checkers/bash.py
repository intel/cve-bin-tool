#!/usr/bin/python3

"""
CVE checker for bash

https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-21050/GNU-Bash.html

"""
from . import Checker


class BashChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"bash"]
    VERSION_PATTERNS = [r"Bash version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnu", "bash")]
