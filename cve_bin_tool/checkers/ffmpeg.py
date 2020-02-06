#!/usr/bin/python3

"""
CVE checker for ffmpeg

References:
https://www.ffmpeg.org/
https://www.cvedetails.com/vulnerability-list/vendor_id-3611/Ffmpeg.html

Note: Some of the "first vulnerable in" data may not be entered correctly.
"""
from ..util import regex_find


def get_version(lines, filename):
    """returns version information for ffmpeg as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be ffmpeg if ffmpeg is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of ffmpeg or contains one
    version gives the actual version number

    VPkg: ffmpeg, ffmpeg
    """
    contains_ffmpeg = "Codec '%s' is not recognized by FFmpeg." in lines
    version_regex = [r"%s version ([0-9]+\.[0-9]+\.[0-9]+)"]
    version_info = dict()
    if filename[::-1].startswith(("ffmpeg")[::-1]):
        version_info["is_or_contains"] = "is"
    elif contains_ffmpeg:
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "ffmpeg"
        version_info["version"] = regex_find(lines, *version_regex)

    return version_info
