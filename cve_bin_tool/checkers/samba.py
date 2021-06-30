# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for samba

https://www.cvedetails.com/product/171/Samba-Samba.html?vendor_id=102

https://www.samba.org/~ab/output/htmldocs/Samba3-HOWTO/compiling.html also
lists "winbindd" and "nmbd" as necessary to configure in startup along with smbd.
But these files do not have the strings which match the signatures in regex. 
That is why they have not been added in FILENAME_PATTERNS. 

"""
from cve_bin_tool.checkers import Checker


class SambaChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [
        r"smbd",
        r"smbtree",
        r"smbget",
        r"smbstatus",
        r"smbspool",
        r"smbpasswd",
        r"smbcquotas",
        r"smbcontrol",
        r"smbclient",
        r"smbcacls",
        r"sharesec",
    ]
    VERSION_PATTERNS = [r"SAMBA_([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("samba", "samba")]
