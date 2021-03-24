# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

# !/usr/bin/env python3
"""
CVE checker for Gstreamer

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-9481/Gstreamer.html
"""
from cve_bin_tool.checkers import Checker


class GstreamerChecker(Checker):
    CONTAINS_PATTERNS = [
        r"http://bugzilla.gnome.org/enter_bug.cgi?product=GStreamer",
    ]
    FILENAME_PATTERNS = [r"gstreamer"]
    VERSION_PATTERNS = [r"libgstreamer-((\d+\.)+\d+)"]
    VENDOR_PRODUCT = [("gstreamer_project", "gstreamer")]
