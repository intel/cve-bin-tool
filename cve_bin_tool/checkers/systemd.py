# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

# pylint: disable=invalid-name
"""
CVE checker for systemd

https://www.cvedetails.com/product/38088/Freedesktop-Systemd.html?vendor_id=7971
"""

from cve_bin_tool.checkers import Checker

from ..util import regex_find


class SystemdChecker(Checker):
    CONTAINS_PATTERNS = [
        r"sd_bus_error_copy",
        r"sd_bus_error_is_set",
        r"sd_bus_error_add_map",
    ]
    FILENAME_PATTERNS = [r"libsystemd.so."]
    VERSION_PATTERNS = [
        r"LIBSYSTEMD_([0-4]+[0-9]+[0-9]+)",
        r"^systemd (\d{2,4})$",
        r"libsystemd-shared-([0-9]+)\.so",  # patterns like this aren't ideal
        r"systemd-[a-z]+-([0-9]+)\.so",  # patterns like this aren't ideal
        r"udev-([0-9]+)\.so",  # patterns like this aren't ideal
        r"systemd v([0-9]+).* running in ",
        r"pam_systemd.so-([0-9]+)\.",
    ]
    VENDOR_PRODUCT = [("freedesktop", "systemd")]

    """
    Using filenames (containing patterns like '.so' etc.) in the binaries as VERSION_PATTERNS aren't ideal.
    The reason behind this is that these might depend on who packages the file (like it 
    might work on fedora but not on ubuntu)
    """

    def get_version(self, lines, filename):
        def guess_contains_systemd(lines):
            """Tries to determine if a file includes systemd"""
            for line in lines:
                if "sd_bus_error_copy" in line:
                    return 1
                if "sd_bus_error_is_set" in line:
                    return 1
                if "sd_bus_error_add_map" in line:
                    return 1
            return 0

        version_info = {}

        if "libsystemd.so." in filename:
            version_info["is_or_contains"] = "is"

        elif guess_contains_systemd(lines):
            version_info["is_or_contains"] = "contains"

        if "is_or_contains" in version_info:
            version_info["modulename"] = "systemd"
            version_info["version"] = regex_find(
                sorted(lines, reverse=True), self.VERSION_PATTERNS
            )

        return version_info
