# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libbpg

https://www.cvedetails.com/product/40429/Libbpg-Project-Libbpg.html?vendor_id=16997

"""
from cve_bin_tool.checkers import Checker


class LibbpgChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"bpgenc"]
    VERSION_PATTERNS = [r"libbpg-([0-9]+\.[0-9]+(\.[0-9]+))"]
    VENDOR_PRODUCT = [("libbpg_project", "libbpg")]
