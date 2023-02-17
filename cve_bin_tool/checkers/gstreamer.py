# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for Gstreamer

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-9481/Gstreamer.html
https://www.cvedetails.com/product/35669/Gstreamer-Project-Gstreamer.html?vendor_id=16047
"""
from cve_bin_tool.checkers import Checker


class GstreamerChecker(Checker):
    CONTAINS_PATTERNS = [
        r"http://bugzilla.gnome.org/enter_bug.cgi?product=GStreamer",
    ]
    FILENAME_PATTERNS = [r"gstreamer"]
    VERSION_PATTERNS = [
        r"((\d+\.)+\d+)[a-zA-Z \r\n]*GStreamer ",
        r"gstreamer[a-zA-Z \r\n]+((\d+\.)+\d+)",
    ]
    VENDOR_PRODUCT = [("gstreamer", "gstreamer"), ("gstreamer_project", "gstreamer")]
