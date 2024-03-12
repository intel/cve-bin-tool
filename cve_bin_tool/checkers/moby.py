# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for moby:
https://www.cvedetails.com/version-list/17212/41384/1/Mobyproject-Moby.html
"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MobyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [
        r"docker",
        r"dockerd",
        r"docker-init",
        r"docker-proxy",
    ]
    VERSION_PATTERNS: list[str] = [
        r"moby-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT: list[tuple[str, str]] = [
        ("mobyproject", "moby"),
    ]
