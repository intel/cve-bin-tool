#!/usr/bin/python3

"""
CVE checker for libdb (berkeley db)
CVE list: https://www.cvedetails.com/vulnerability-list/vendor_id-93/product_id-32070/Oracle-Berkeley-Db.html
"""
from . import Checker


class LibdbChecker(Checker):
    CONTAINS_PATTERNS = [
        "BDB1568 Berkeley DB library does not support DB_REGISTER on this system",
        "BDB1507 Thread died in Berkeley DB library",
        "Berkeley DB ",
    ]
    FILENAME_PATTERNS = [r"libdb-"]
    VERSION_PATTERNS = [
        r"Berkeley DB ([0-9]+\.[0-9]+\.[0-9]+):",  # short version as backup. we mostly want the long below.
        r"Berkeley DB .+, library version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):",
    ]
    VENDOR_PRODUCT = [("oracle", "berkeley_db")]
