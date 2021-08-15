# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cups

https://www.cvedetails.com/product/1219/Easy-Software-Products-Cups.html?vendor_id=713

"""

from cve_bin_tool.checkers import Checker


class CupsChecker(Checker):
    CONTAINS_PATTERNS = [
        r"No limit for CUPS-Get-Document defined in policy %s and no suitable template found.",
        r"\*%%%%%%%% Created by the CUPS PPD Compiler CUPS v([0-9]+\.[0-9]+\.[0-9]+)"
        # r"Unable to edit cupsd.conf files larger than 1MB",
        # r"The web interface is currently disabled. Run \"cupsctl WebInterface=yes\" to enable it.",
        # r"cupsdAddSubscription: Reached MaxSubscriptions %d \(count=%d\)",
    ]
    FILENAME_PATTERNS = [r"cups"]
    VERSION_PATTERNS = [r"CUPS v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("easy_software_products", "cups")]
