# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for systemd

https://www.cvedetails.com/product/34874/Systemd-Project-Systemd.html?vendor_id=15978
"""
from cve_bin_tool.checkers import Checker


class SystemdChecker(Checker):
    CONTAINS_PATTERNS = [
        r"sd_bus_error_copy",
        r"sd_bus_error_is_set",
        r"sd_bus_error_add_map",
    ]
    FILENAME_PATTERNS = [r"libsystemd.so."]
    VERSION_PATTERNS = [
        r"\r?\nsystemd (\d{2,4})",
        r"libsystemd-shared-([0-9]+)\.so",  # patterns like this aren't ideal
        r"systemd-[a-z]+-([0-9]+)\.so",  # patterns like this aren't ideal
        r"udev-([0-9]+)\.so",  # patterns like this aren't ideal
        r"systemd v([0-9]+).* running in ",
        r"pam_systemd.so-([0-9]+)\.",
    ]
    VENDOR_PRODUCT = [("systemd_project", "systemd")]

    """
    Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
    The reason behind this is that these might depend on who packages the file (like it
    might work on fedora but not on ubuntu)
    """
