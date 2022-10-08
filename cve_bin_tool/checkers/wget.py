# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for wget:

https://www.cvedetails.com/product/5923/Wget-Wget.html?vendor_id=3385

"""
from cve_bin_tool.checkers import Checker


class WgetChecker(Checker):
    CONTAINS_PATTERNS = [
        r"GNU Wget is a file retrieval utility which can use either the HTTP or",
        r"FTP protocols. Wget features include the ability to work in the",
    ]
    FILENAME_PATTERNS = [r"wget"]
    VERSION_PATTERNS = [r"wget-([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("gnu", "wget"), ("wget", "wget")]
