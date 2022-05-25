# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bash

https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-21050/GNU-Bash.html

"""
from cve_bin_tool.checkers import Checker


class BashChecker(Checker):
    CONTAINS_PATTERNS = [
        r"save_bash_input: buffer already exists for new fd %d",
        r"cannot allocate new file descriptor for bash input from fd %d",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"bash manual page for the complete specification.",
        # r"bash_execute_unix_command: cannot find keymap for command",
    ]
    FILENAME_PATTERNS = [r"bash"]
    VERSION_PATTERNS = [
        r"Bash version ([0-9]+\.[0-9]+\.[0-9]+)"
    ]  # this version string is extracted from "@(#)Bash version 5.1.4(1) release GNU"
    VENDOR_PRODUCT = [("gnu", "bash")]
