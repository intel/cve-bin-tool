#!/usr/bin/python3

"""
CVE checker for libvirt

https://www.cvedetails.com/product/15743/Libvirt-Libvirt.html?vendor_id=8917

"""
from . import Checker


class LibvirtChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [
        r"libvirtd",
        r"libvirt.so",
    ]
    VERSION_PATTERNS = [r"LIBVIRT_PRIVATE_([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libvirt", "libvirt")]
