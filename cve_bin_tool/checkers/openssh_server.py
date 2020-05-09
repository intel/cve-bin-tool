#!/usr/bin/python3
import os

"""
CVE checker for openssh

References:
https://www.cvedetails.com/product/585/Openbsd-Openssh.html?vendor_id=97
"""
from . import Checker


class OpensshServerChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"sshd"]
    VERSION_PATTERNS = [r"OpenSSH_([0-9]+\.[0-9]+[0-9a-z\s]*)"]
    VENDOR_PACKAGE = [("openbsd", "openssh")]
    MODULE_NAME = "openssh-server"
