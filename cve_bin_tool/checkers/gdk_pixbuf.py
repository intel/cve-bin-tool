# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gdk-pixbuf

https://www.cvedetails.com/product/22543/Gnome-Gdk-pixbuf.html?vendor_id=283

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GdkPixbufChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"dest_pixbuf\)\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9/!=&_>' \(\)\-\.\t\r\n]*GDK_PIXBUF_MAGIC_NUMBER",
    ]
    VENDOR_PRODUCT = [("gnome", "gdk-pixbuf")]
