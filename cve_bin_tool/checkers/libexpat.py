# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

r"""
CVE checker for libexpat

References:
http://www.cvedetails.com/vulnerability-list/vendor_id-16735/product_id-39003/Libexpat-Project-Libexpat.html
https://github.com/libexpat/libexpat/blob/master/expat/Changes

RSS feeds:
http://www.cvedetails.com/vulnerability-feed.php?vendor_id=12682&product_id=0&version_id=0&orderby=3&cvssscoremin=0
http://www.cvedetails.com/vulnerability-feed.php?vendor_id=16735&product_id=0&version_id=0&orderby=3&cvssscoremin=0

Easiest way to check CVEs is currently the Changes.txt file.  You can pinpoint the CVEs using grep as follows:
grep 'Release\|CVE' Changes.txt

Which will give you output like...

Release 2.2.5 Tue October 31 2017
Release 2.2.4 Sat August 19 2017
Release 2.2.3 Wed August 2 2017
             #82  CVE-2017-11742 -- Windows: Fix DLL hijacking vulnerability
Release 2.2.2 Wed July 12 2017
Release 2.2.1 Sat June 17 2017
                  CVE-2017-9233 -- External entity infinite loop DoS
(etc.)
"""
from cve_bin_tool.checkers import Checker


class LibexpatChecker(Checker):
    CONTAINS_PATTERNS = [
        r"reserved prefix (xml) must not be undeclared or bound to another namespace name",
        r"cannot change setting once parsing has begun",
        "requested feature requires XML_DTD support in Expat",
    ]
    FILENAME_PATTERNS = [r"libexpat.so"]
    VERSION_PATTERNS = [r"expat_([012]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libexpat_project", "libexpat")]
