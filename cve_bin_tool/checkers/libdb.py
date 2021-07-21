# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libdb (berkeley db)
CVE list: https://www.cvedetails.com/vulnerability-list/vendor_id-93/product_id-32070/Oracle-Berkeley-Db.html
"""
from cve_bin_tool.checkers import Checker


class LibdbChecker(Checker):
    CONTAINS_PATTERNS = [
        "BDB1568 Berkeley DB library does not support DB_REGISTER on this system",
        "BDB1507 Thread died in Berkeley DB library",
        "Berkeley DB ",
    ]
    FILENAME_PATTERNS = [r"libdb-"]
    VERSION_PATTERNS = [
        r"Berkeley DB .+, library version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):",
        r"Berkeley DB ([0-9]+\.[0-9]+\.[0-9]+):",  # short version as backup. we mostly want the long above.
    ]
    VENDOR_PRODUCT = [("oracle", "berkeley_db")]
