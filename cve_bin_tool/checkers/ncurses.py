#!/usr/bin/python3

"""
CVE checker for Ncurses

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-38464/GNU-Ncurses.html

RSS feed: http://www.cvedetails.com/vulnerability-feed.php?vendor_id=72&product_id=38464&version_id=0&orderby=3&cvssscoremin=0

"""
from ..util import regex_find


def guess_contains_ncurses(lines):
    """Tries to determine if a file includes Ncurses
    """
    for line in lines:
        if "_nc_first_name" in line:
            return 1
        if "_nc_infotocap" in line:
            return 1
        if "if NCURSES_XNAMES" in line:
            return 1

    return 0


def get_version(lines, filename):
    """returns version information for Ncurses as found in a given file.
    CURRENTLY SUPPORTS VERSIONS 6.0+
    (may work for versions < 6.0 in some cases)
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be ncurses if Ncurses is found (and blank otherwise)
    is_or_contains idicates if the file is a copy of Ncurses or contains one
    version gives the actual version number

    VPkg: gnu, ncurses
    """
    # string found in arch linux's pkg
    regex = [r"ncurses ([0-9]+\.[0-9]+)"]
    # strings found in fedora's pkg
    regex1 = [r"infocmp-([0-9]+\.[0-9]+)"]
    version_info = dict()
    if any(
        s in filename
        for s in (
            "libcurses",
            "libform",
            "libmenu",
            "libncurses",
            "libncurses++",
            "libpanel",
            "libcursesw",
            "libformw",
            "libmenuw",
            "libncursesw",
            "libncurses++w",
            "libpanelw",
        )
    ):
        version_info["is_or_contains"] = "is"
    elif guess_contains_ncurses(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "ncurses"
        version_info["version"] = regex_find(lines, *regex)
        # tries alternate regex
        if version_info["version"] == "UNKNOWN":
            version_info["version"] = regex_find(lines, *regex1)

    return version_info
