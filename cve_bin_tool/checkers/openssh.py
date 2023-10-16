# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openssh

References:
https://www.cvedetails.com/product/585/Openbsd-Openssh.html?vendor_id=97
https://www.cvedetails.com/product/12081/Openssh-Openssh.html?vendor_id=7161
"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpensshChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS = [
        r"scp",
        r"sftp",
        r"ssh-add",
        r"ssh-agent",
        r"ssh-argv0",
        r"ssh-copy-id",
        r"ssh-keygen",
        r"ssh-keyscan",
        r"ssh",
        r"slogin",
        r"sshd",
    ]
    VERSION_PATTERNS = [r"\r?\nOpenSSH_([0-9]+\.[0-9]+(\.[0-9]+)?p[0-9]+)(?:\r?\n| )"]
    VENDOR_PRODUCT = [("openbsd", "openssh"), ("openssh", "openssh")]
