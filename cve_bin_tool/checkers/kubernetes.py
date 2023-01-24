# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for kubernetes

https://www.cvedetails.com/product/34016/Kubernetes-Kubernetes.html?vendor_id=15867

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class KubernetesChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"kubectl"]
    VERSION_PATTERNS = [
        r"kubernetes-([0-9]+.[0-9]+(.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [("kubernetes", "kubernetes")]
