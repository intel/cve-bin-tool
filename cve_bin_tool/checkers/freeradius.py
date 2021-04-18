# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for freeradius

https://www.cvedetails.com/product/1805/Freeradius-Freeradius.html?vendor_id=1039

"""
from cve_bin_tool.checkers import Checker


class FreeradiusChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"radiusd"]
    VERSION_PATTERNS = [r"FreeRADIUS Version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("freeradius", "freeradius")]
