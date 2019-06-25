# pylint: disable=invalid-name
"""
CVE checker for systemd

https://www.cvedetails.com/product/38088/Freedesktop-Systemd.html?vendor_id=7971
"""
from ..util import regex_find


def guess_contains_systemd(lines):
    """Tries to determine if a file includes systemd
    """
    for line in lines:
        if "sd_bus_error_copy" in line:
            return 1
        if "sd_bus_error_is_set" in line:
            return 1
        if "sd_bus_error_add_map" in line:
            return 1
    return 0


def get_version(lines, filename):
    """returns version information for systemd as found in a given file.
    The version info is returned as a tuple:
        [modulename, is_or_contains, version]

    modulename will be systemd if systemd is found (and blank otherwise)
    is_or_contains indicates if the file is a copy of systemd or contains one
    version gives the actual version number

    VPkg: freedesktop, systemd
    """
    regex = [r"LIBSYSTEMD_([0-4]+[0-9]+[0-9]+)", "^systemd (\d{2,4})$"]
    version_info = dict()
    if "libsystemd.so." in filename:
        version_info["is_or_contains"] = "is"
    elif guess_contains_systemd(lines):
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "systemd"
        version_info["version"] = regex_find(lines, *regex)
    return version_info
