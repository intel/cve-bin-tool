# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sudo
References:
https://www.sudo.ws/
https://www.cvedetails.com/vulnerability-list/vendor_id-15714/product_id-32625/Sudo-Project-Sudo.html
"""
from cve_bin_tool.checkers import Checker


class SudoChecker(Checker):
    CONTAINS_PATTERNS = [
        r"sudo_debug_exit_str_masked_v1",
        r"sudo_debug_set_active_instance_v1",
        r"sudo_fatal_callback_register_v1",
    ]
    FILENAME_PATTERNS = [
        r"sudo_logsrvd",
        r"sudo_sendlog",
        r"sudoers.so",
    ]
    VERSION_PATTERNS = [
        r"Sudo Audit Server ([0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?)",
        r"Sudo Sendlog ([0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?)",
        r"sudoers ([0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [
        ("sudo_project", "sudo"),
    ]
