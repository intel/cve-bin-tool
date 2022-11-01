# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openvpn

https://www.cvedetails.com/product/5768/Openvpn-Openvpn.html?vendor_id=3278

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenvpnChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [r"openvpn"]
    VERSION_PATTERNS = [r"OpenVPN ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openvpn", "openvpn")]
