# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for seahorse:

https://www.cvedetails.com/product/51227/?q=Seahorse

"""
from cve_bin_tool.checkers import Checker


class SeahorseChecker(Checker):
    CONTAINS_PATTERNS = [
        r"cannot display progress because seahorse window has no progress widget"
    ]
    FILENAME_PATTERNS = [r"seahorse"]
    VERSION_PATTERNS = [r"seahorse ([0-9]+\.[0-9]+(\.[0-9]+)?)\r?\n"]
    VENDOR_PRODUCT = [("gnome", "seahorse")]
