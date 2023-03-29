# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Nano

https://www.cvedetails.com/product/19122/?q=Nano

"""
from cve_bin_tool.checkers import Checker


class NanoChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Usage: nano \[OPTIONS\] \[\[\+LINE\[,COLUMN\]\] FILE\]...",
        r"Welcome to nano.  For basic help, type Ctrl+G.",
        r"When a filename is '-', nano reads data from standard input.",
        r"If needed, use nano with the -I option to adjust your nanorc settings.",
        r"Nano will be unable to load or save search history or cursor positions.",
    ]
    FILENAME_PATTERNS = [
        r"nano",
    ]
    VERSION_PATTERNS = [r"GNU nano ([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("gnu", "nano")]
