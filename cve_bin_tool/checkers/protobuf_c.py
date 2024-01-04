# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for protobuf-c

https://www.cvedetails.com/product/116953/Protobuf-c-Project-Protobuf-c.html?vendor_id=27533

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ProtobufCChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"protobuf-c[a-zA-Z0-9@`&_:.()<>= \-\t\r\n]*\r?\n([0-9]+\.[0-9]+\.[0-9]+)"
    ]
    VENDOR_PRODUCT = [("protobuf-c_project", "protobuf-c")]
