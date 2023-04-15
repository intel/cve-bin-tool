# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ftp

https://www.cvedetails.com/product/12667/Netkit-ftp-Netkit-Ftp.html?vendor_id=7511

"""
from cve_bin_tool.checkers import Checker


class NetkitFtpChecker(Checker):
    CONTAINS_PATTERNS = [
        r"-p: enable passive mode \(default for ftp and pftp\)",
        r"ftp: no answer from ftp-server \(more than 5 sec\).",
    ]
    FILENAME_PATTERNS = [r"ftp"]
    VERSION_PATTERNS = [r"\$NetKit: netkit-ftp-([0-9]+\.[0-9]+) \$"]
    VENDOR_PRODUCT = [("netkit-ftp", "netkit_ftp")]
