# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libvncserver

https://www.cvedetails.com/product/8258/Libvncserver-Libvncserver.html?vendor_id=4842
https://www.cvedetails.com/product/35486/Libvncserver-Project-Libvncserver.html?vendor_id=16014
https://www.cvedetails.com/product/68326/Libvnc-Project-Libvncserver.html?vendor_id=21769

"""
from cve_bin_tool.checkers import Checker


class LibvncserverChecker(Checker):
    CONTAINS_PATTERNS = [
        r"-desktop name          VNC desktop name \(default \"LibVNCServer\"\)"
    ]
    FILENAME_PATTERNS = [r"libvncserver"]
    VERSION_PATTERNS = [r"LibVNCServer ([0-9]+\.[0-9]+(\.[0-9]+))"]
    VENDOR_PRODUCT = [
        ("libvncserver", "libvncserver"),
        ("libvncserver_project", "libvncserver"),
        ("libvnc_project", "libvncserver"),
    ]
