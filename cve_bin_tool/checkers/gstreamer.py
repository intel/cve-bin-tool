# !/usr/bin/env python3
"""
CVE checker for Gstreamer

References:
https://www.cvedetails.com/vulnerability-list/vendor_id-9481/Gstreamer.html
"""
from ..util import regex_find


def guess_contains(lines):
    """Tries to determine if a file includes expat
    """
    count = 0
    should_contain = [
        "http://bugzilla.gnome.org/enter_bug.cgi?product=GStreamer",
        "LGPL",
    ]
    for line in lines:
        for i in should_contain:
            if i in line:
                count += 1
    return True if count >= len(should_contain) else False


def get_version(lines, filename):
    """returns version information for gstreamer as found in a given file.
    VPkg: gstreamer_project, gstreamer
    """
    regex = [r"libgstreamer-((\d+\.)+\d+)"]
    version_info = dict()
    if "gstreamer" in filename:
        version_info["is_or_contains"] = "is"

    elif guess_contains(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "gstreamer"
        version_info["version"] = regex_find(lines, *regex)

    return version_info
