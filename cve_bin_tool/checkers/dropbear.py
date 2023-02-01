# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dropbear:

https://www.cvedetails.com/product/33536/Dropbear-Ssh-Project-Dropbear-Ssh.html?vendor_id=15806

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DropbearChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"SSH-2.0-dropbear_([0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+)\r?\nDropbear",
    ]
    VENDOR_PRODUCT = [("dropbear_ssh_project", "dropbear_ssh")]
