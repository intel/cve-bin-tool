#!/usr/bin/env python3
"""
CVE checker for Bluez
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-8316/product_id-35116/Bluez-Bluez.html

"""
from ..util import regex_find


def get_version(lines, filename):
    """Bluetoothctl will work for Version 5.0+

       VPkg: bluez, bluez
    """
    regex = [r"bluetoothctl: ([5]+\.[0-9]+\.[0-9]+)", r"bluetoothctl: ([5]+\.[0-9]+)"]
    version_info = dict()
    if filename.startswith("bluetoothctl"):
        version_info["is_or_contains"] = "is"
    elif "libbluetooth.so" in filename:
        version_info["is_or_contains"] = "is"

    version = regex_find(lines, *regex)
    if version != "UNKNOWN":
        version_info["is_or_contains"] = "contains"

    if "is_or_contains" in version_info:
        version_info["modulename"] = "bluetoothctl"
        version_info["version"] = version

    return version_info
