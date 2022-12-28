# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for git

https://www.cvedetails.com/product/7026/GIT-GIT.html?vendor_id=4008
https://www.cvedetails.com/product/32706/Git-Project-GIT.html?vendor_id=15726
https://www.cvedetails.com/product/33590/Git-scm-GIT.html?vendor_id=15815

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GitChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"git/([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [
        ("git", "git"),
        ("git_project", "git"),
        ("git-scm", "git"),
    ]
