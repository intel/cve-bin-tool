#!/usr/bin/env python3
"""
CVE checker for Bluez
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-8316/product_id-35116/Bluez-Bluez.html

"""
from . import Checker


class BluezChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"bluetoothctl", r"libbluetooth.so"]
    VERSION_PATTERNS = [
        r"bluetoothctl: ([5]+\.[0-9]+\.[0-9]+)",
        r"bluetoothctl: ([5]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("bluez", "bluez")]
