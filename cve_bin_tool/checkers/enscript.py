# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for enscript

https://www.cvedetails.com/product/1800/?q=Enscript

"""
from cve_bin_tool.checkers import Checker


class EnscriptChecker(Checker):
    CONTAINS_PATTERNS = [
        r"set the PostScript language level that enscript",
        r"or set the environment variable `ENSCRIPT_LIBRARY' to point to your library directory.",
    ]
    FILENAME_PATTERNS = [r"enscript"]
    VERSION_PATTERNS = [r"GNU Enscript ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnu", "enscript")]
