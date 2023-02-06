# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for suricata

https://www.cvedetails.com/product/27771/Openinfosecfoundation-Suricata.html?vendor_id=13364
https://www.cvedetails.com/product/45965/Suricata-ids-Suricata.html?vendor_id=17948
https://www.cvedetails.com/product/57121/Oisf-Suricata.html?vendor_id=17892

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SuricataChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"suricata\-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+) RELEASE\r?\nClosing Suricata",
    ]
    VENDOR_PRODUCT = [
        ("openinfosecfoundation", "suricata"),
        ("oisf", "suricata"),
        ("suricata-ids", "suricata"),
    ]
