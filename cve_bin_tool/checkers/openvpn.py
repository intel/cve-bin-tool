#!/usr/bin/python3

"""
CVE checker for openvpn

https://www.cvedetails.com/product/5768/Openvpn-Openvpn.html?vendor_id=3278

"""
from . import Checker


class OpenvpnChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"openvpn"]
    VERSION_PATTERNS = [r"OpenVPN ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openvpn", "openvpn")]
