# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bind

https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64

"""
from cve_bin_tool.checkers import Checker


class BindChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"named"]
    VERSION_PATTERNS = [r"BIND ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("isc", "bind")]
