# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for hunspell

https://www.cvedetails.com/product/60308/?q=Hunspell

"""
from cve_bin_tool.checkers import Checker


class HunspellChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Example: hunspell -d en_US file.txt    # interactive spelling"
    ]
    FILENAME_PATTERNS = [r"hunspell"]
    VERSION_PATTERNS = [
        r"@\(#\) International Ispell Version .+ \(but really Hunspell ([0-9]+\.[0-9]+\.[0-9]+)\)"
    ]
    VENDOR_PRODUCT = [("hunspell_project", "hunspell")]
