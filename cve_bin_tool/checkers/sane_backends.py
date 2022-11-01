# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sane-backends

https://www.cvedetails.com/vendor/16236/?q=Sane-backends+Project

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SaneBackendsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"sane-find-scanner"]
    VERSION_PATTERNS = [r"sane-backends ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("sane-backends_project", "sane-backends")]
