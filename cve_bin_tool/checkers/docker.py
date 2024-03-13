# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for docker
https://www.cvedetails.com/product/28125/Docker-Docker.html?vendor_id=13534
"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DockerChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"docker"]
    VERSION_PATTERNS: list[str] = [
        r"docker-ce-([0-9]+\.[0-9]+\.[0-9]+)",
        r"moby-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT: list[tuple[str, str]] = [
        ("docker", "docker"),
    ]
