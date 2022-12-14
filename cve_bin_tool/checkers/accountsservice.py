# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for accountservice

https://www.cvedetails.com/product/63450/?q=accountsservice
https://www.cvedetails.com/product/27451/Canonical-Accountsservice.html?vendor_id=4781
https://www.cvedetails.com/product/48266/Freedesktop-Accountsservice.html?vendor_id=7971
https://www.cvedetails.com/product/63450/Accountsservice-Project-Accountsservice.html?vendor_id=21123

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AccountsserviceChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"accountsservice"]
    VERSION_PATTERNS = [r"accounts-daemon ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("canonical", "accountsservice"),
        ("ray_stode", "accountsservice"),
        ("accountsservice_project", "accountsservice"),
        ("freedesktop", "accountsservice"),
    ]
