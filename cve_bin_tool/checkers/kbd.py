# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for kbd

https://www.cvedetails.com/product/27439/?q=KBD

"""
from cve_bin_tool.checkers import Checker


class KbdChecker(Checker):
    CONTAINS_PATTERNS = [r"KDGKBDIACR\(UC\): %s: Unable to get accent table"]
    FILENAME_PATTERNS = [r"kbd"]
    VERSION_PATTERNS = [r"kbd ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("kbd-project", "kbd")]
