# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Ncurses

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-38464/GNU-Ncurses.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=72&product_id=38464&version_id=0&orderby=3&cvssscoremin=0

"""
from cve_bin_tool.checkers import Checker


class NcursesChecker(Checker):
    CONTAINS_PATTERNS = [r"_nc_first_name", r"_nc_infotocap", r"if NCURSES_XNAMES"]
    FILENAME_PATTERNS = [
        r"libcurses",
        r"libform",
        r"libmenu",
        r"libncurses",
        r"libncurses\+{2}",
        r"libpanel",
        r"libcursesw",
        r"libformw",
        r"libmenuw",
        r"libncursesw",
        r"libncurses\+{2}w",
        r"libpanelw",
    ]
    VERSION_PATTERNS = [r"ncurses ([0-9]+\.[0-9]+)", r"infocmp-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnu", "ncurses")]
