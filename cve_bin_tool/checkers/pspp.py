# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for pspp

https://www.cvedetails.com/product/38732/GNU-Pspp.html?vendor_id=72

"""
from cve_bin_tool.checkers import Checker


class PsppChecker(Checker):
    CONTAINS_PATTERNS = [
        r"The PSPP language identifier for the data associated with this window \(e\.g\. dataset name\)",
        r"bug-gnu-pspp@gnu\.org",
    ]
    FILENAME_PATTERNS = [r"libpspp"]
    VERSION_PATTERNS = [r"libpspp-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnu", "pspp")]
