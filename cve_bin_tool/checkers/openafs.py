# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openafs

https://www.cvedetails.com/product/2873/Openafs-Openafs.html?vendor_id=1664

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenafsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"afsd"]
    VERSION_PATTERNS = [r"OpenAFS ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openafs", "openafs")]
