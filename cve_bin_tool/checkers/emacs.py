# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for emacs

https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-741/GNU-Emacs.html

"""
from cve_bin_tool.checkers import Checker


class EmacsChecker(Checker):
    CONTAINS_PATTERNS = [
        r"Bare Emacs (standard Lisp code not loaded)",
        r"Run M-x info RET m emacs RET m emacs invocation RET inside Emacs to",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"Run Emacs, the extensible, customizable, self-documenting real-time",
    ]
    FILENAME_PATTERNS = [r"emacs"]
    VERSION_PATTERNS = [
        r"Id: GNU Emacs ([0-9]+\.[0-9]+)"
    ]  # this version string is extracted from "$Id: GNU Emacs 26.3 (build 1, x86_64-pc-linux-gnu, GTK+ Version 3.24.14)  of 2020-03-26, modified by Debian $"

    VENDOR_PRODUCT = [("gnu", "emacs")]
