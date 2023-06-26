# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for ceph:

https://www.cvedetails.com/product/32692/Redhat-Ceph.html?vendor_id=25
https://www.cvedetails.com/product/81816/Linuxfoundation-Ceph.html?vendor_id=11448
"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CephChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"ceph"]
    VERSION_PATTERNS = [
        r"ceph-([0-9]+.[0-9]+.[0-9]+)",
        r'"name":"ceph","version":"([0-9]+.[0-9]+(.[0-9]+)?)',
    ]
    VENDOR_PRODUCT = [
        ("redhat", "ceph"),
        ("ceph_project", "ceph"),
        ("ceph", "ceph"),
        ("linuxfoundation", "ceph"),
    ]
