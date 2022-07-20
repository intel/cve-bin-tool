# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for systemd

https://www.cvedetails.com/product/38088/Freedesktop-Systemd.html?vendor_id=7971
"""

from re import DOTALL, MULTILINE, compile

from cve_bin_tool.checkers import Checker


class SystemdChecker(Checker):
    CONTAINS_PATTERNS = [
        r"sd_bus_error_copy",
        r"sd_bus_error_is_set",
        r"sd_bus_error_add_map",
    ]
    FILENAME_PATTERNS = [r"libsystemd.so."]
    VERSION_PATTERNS = [
        compile(
            r"LIBSYSTEMD_([0-4]+[0-9]+[0-9]+)(?!.*LIBSYSTEMD_([0-4]+[0-9]+[0-9]+))",
            DOTALL,
        ),
        compile(r"^systemd (\d{2,4})", MULTILINE),
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

    """
    In some packages of systemd the version strings are present in

    ```
    LIBSYSTEMD_209
    LIBSYSTEMD_211
    ...
    LIBSYSTEMD_245
    LIBSYSTEMD_246
    ```

    this way. So we need to make sure the first regex pattern detects the last and latest version string.
    Which is dealt by the regex r"LIBSYSTEMD_([0-4]+[0-9]+[0-9]+)(?!.*LIBSYSTEMD_([0-4]+[0-9]+[0-9]+))".
    The regex uses negative lookahead and DOTALL to detect the last occurring match and returns it.
    """
