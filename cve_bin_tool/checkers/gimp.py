# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gimp

https://www.cvedetails.com/product/17152/Gimp-Gimp.html?vendor_id=9605

"""
from cve_bin_tool.checkers import Checker


class GimpChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"gimp"]
    VERSION_PATTERNS = [r"GIMP ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gimp", "gimp")]
