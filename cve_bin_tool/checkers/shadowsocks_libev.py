# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for shadowsocks-libev

https://www.cvedetails.com/product/41244/Shadowsocks-Shadowsocks-libev.html?vendor_id=17167

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ShadowsocksLibevChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nshadowsocks-libev",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n  usage\:\r?\n    ss-",
    ]
    VENDOR_PRODUCT = [("shadowsocks", "shadowsocks-libev")]
