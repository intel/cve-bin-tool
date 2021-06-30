# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for radare2

https://www.cvedetails.com/product/36037/Radare-Radare2.html?vendor_id=16137

"""
from cve_bin_tool.checkers import Checker


class Radare2Checker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"rafind2"]
    VERSION_PATTERNS = [r"rafind2 v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("radare", "radare2")]
