# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for gupnp

https://www.cvedetails.com/product/95568/?q=Gupnp

"""
from cve_bin_tool.checkers import Checker


class GupnpChecker(Checker):
    CONTAINS_PATTERNS = [
        r"GUPnPContext: Unable to listen on ",
    ]
    FILENAME_PATTERNS = [r"libgupnp"]
    VERSION_PATTERNS = [r"%s GUPnP/([0-9]+\.[0-9]+\.[0-9]+) DLNADOC/"]
    VENDOR_PRODUCT = [("gupnp", "gupnp"), ("gnome", "gupnp")]
