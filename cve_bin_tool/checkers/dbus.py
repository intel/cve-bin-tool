# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dbus

https://www.cvedetails.com/product/5517/D-bus-D-bus.html?vendor_id=3133
https://www.cvedetails.com/product/15107/Freedesktop-Dbus.html?vendor_id=7971
https://www.cvedetails.com/product/23240/Freedesktop-Libdbus.html?vendor_id=7971
https://www.cvedetails.com/product/27993/D-bus-Project-D-bus.html?vendor_id=13442

"""
from cve_bin_tool.checkers import Checker


class DbusChecker(Checker):
    CONTAINS_PATTERNS = [
        r"dbus_connection_get_adt_audit_session_data",
        r"dbus_connection_set_dispatch_status_function",
        # Alternate optional contains patterns,
        # see https://github.com/intel/cve-bin-tool/tree/main/cve_bin_tool/checkers#helper-script for more details
        # r"dbus_connection_set_max_received_unix_fds",
        # r"dbus_connection_set_windows_user_function",
        # r"_dbus_connection_get_linux_security_label",
        # r"_dbus_connection_set_pending_fds_function",
        # r"_dbus_credentials_new_from_current_process",
        # r"_dbus_hash_table_insert_string_preallocated",
        # r"org\.freedesktop\.DBus\.Error\.LimitsExceeded",
        # r"org\.freedesktop\.DBus\.Error\.Spawn\.ExecFailed",
    ]
    FILENAME_PATTERNS = [r"dbus"]
    VERSION_PATTERNS = [
        r"LIBDBUS_PRIVATE_([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"libdbus ([0-9]+\.[0-9]+(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [
        ("d-bus", "d-bus"),
        ("d-bus_project", "d-bus"),
        ("freedesktop", "dbus"),
        ("freedesktop", "libdbus"),
    ]
