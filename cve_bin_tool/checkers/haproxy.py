# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for haproxy

https://www.cvedetails.com/product/22372/Haproxy-Haproxy.html?vendor_id=11969

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class HaproxyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"haproxy"]
    VERSION_PATTERNS = [
        r"HA-Proxy version ([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)-?[0-9]*\r?\nHAProxy version follows",
    ]
    VENDOR_PRODUCT = [("haproxy", "haproxy")]
