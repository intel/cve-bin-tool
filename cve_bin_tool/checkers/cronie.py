# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cronie

https://www.cvedetails.com/product/18871/?q=Cronie

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CronieChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"cronnext", r"crontab", r"crond"]
    VERSION_PATTERNS = [r"cronie ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("fedorahosted", "cronie")]
