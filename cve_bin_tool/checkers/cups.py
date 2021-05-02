# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cups

https://www.cvedetails.com/product/1219/Easy-Software-Products-Cups.html?vendor_id=713

"""

from cve_bin_tool.checkers import Checker


class CupsChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"cupsd"]
    VERSION_PATTERNS = [r"CUPS v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("easy_software_products", "cups")]
