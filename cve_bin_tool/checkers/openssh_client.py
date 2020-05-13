#!/usr/bin/python3
import os

"""
CVE checker for openssh

References:
https://www.cvedetails.com/product/585/Openbsd-Openssh.html?vendor_id=97
"""
from . import Checker


class OpensshClientChecker(Checker):
    CONTAINS_PATTERNS = [
        r"OpenSSH_([0-9]+\.[0-9]+[0-9a-z\s]*)",
    ]
    FILENAME_PATTERNS = [
        r"scp",
        r"sftp",
        r"ssh-add",
        r"ssh-agent",
        r"ssh-argv0",
        r"ssh-copy-id",
        r"ssh-keygen",
        r"ssh-keyscan",
        r"ssh",
        r"slogin",
    ]
    VERSION_PATTERNS = [r"OpenSSH_([0-9]+\.[0-9]+[0-9a-z\s]*)"]
    VENDOR_PACKAGE = [("openbsd", "openssh")]
    MODULE_NAME = "openssh-client"
