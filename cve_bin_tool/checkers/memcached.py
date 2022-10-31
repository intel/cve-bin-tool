# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for memcached

https://www.cvedetails.com/product/26610/Memcached-Memcached.html?vendor_id=12993

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MemcachedChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"memcached"]
    VERSION_PATTERNS = [r"memcached ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("memcached", "memcached")]
