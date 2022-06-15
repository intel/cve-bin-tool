# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rust:

https://www.cvedetails.com/vulnerability-list/vendor_id-19029/product_id-48677/Rust-lang-Rust.html
"""
from cve_bin_tool.checkers import Checker


class RustChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Default passes for rustdoc:",
        r"src/librustdoc/json/mod.rs",
    ]
    FILENAME_PATTERNS = [r"rust"]
    VERSION_PATTERNS = [r"rustc-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("rust-lang", "rust")]
