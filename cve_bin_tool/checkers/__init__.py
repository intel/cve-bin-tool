# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" CVE Checkers """
import collections
import re

from cve_bin_tool.error_handler import InvalidCheckerError
from cve_bin_tool.util import regex_find

__all__ = [
    "Checker",
    "VendorProductPair",
    "accountsservice",
    "avahi",
    "bash",
    "bind",
    "binutils",
    "bolt",
    "bubblewrap",
    "busybox",
    "bzip2",
    "cryptsetup",
    "cups",
    "curl",
    "dnsmasq",
    "dovecot",
    "dpkg",
    "enscript",
    "expat",
    "ffmpeg",
    "freeradius",
    "ftp",
    "gcc",
    "gimp",
    "gnupg",
    "gnutls",
    "glibc",
    "gpgme",
    "gstreamer",
    "haproxy",
    "hostapd",
    "icecast",
    "icu",
    "irssi",
    "kerberos",
    "libarchive",
    "libdb",
    "libgcrypt",
    "libjpeg",
    "libnss",
    "libsndfile",
    "libsoup",
    "libssh2",
    "libtiff",
    "libvirt",
    "libxslt",
    "lighttpd",
    "logrotate",
    "mariadb",
    "memcached",
    "mysql",
    "ncurses",
    "nessus",
    "netpbm",
    "nginx",
    "node",
    "ntp",
    "openafs",
    "openjpeg",
    "openldap",
    "openssh",
    "openssl",
    "openswan",
    "openvpn",
    "p7zip",
    "png",
    "polarssl_fedora",
    "postgresql",
    "pspp",
    "python",
    "qt",
    "radare2",
    "rsyslog",
    "samba",
    "sqlite",
    "strongswan",
    "subversion",
    "syslogng",
    "systemd",
    "tcpdump",
    "varnish",
    "webkitgtk",
    "wireshark",
    "wpa_supplicant",
    "xerces",
    "xml2",
    "zlib",
]

VendorProductPair = collections.namedtuple("VendorProductPair", ["vendor", "product"])


class CheckerMetaClass(type):
    def __init__(cls, name, bases, namespace, **kwargs):
        """
        Needed for compatibility with Python 3.5
        """
        super().__init__(name, bases, namespace)

    def __new__(cls, name, bases, props):
        # Create the class
        cls = super().__new__(cls, name, bases, props)
        # HACK Skip validation if this class is the base class
        if name == "Checker":
            return cls
        # Validate that we have at least one vendor product pair
        if len(cls.VENDOR_PRODUCT) < 1:
            raise AssertionError(f"{name} needs at least one vendor product pair")
        # Validate that each vendor product pair is of length 2
        cls.VENDOR_PRODUCT = list(
            map(lambda vpkg: VendorProductPair(*vpkg), cls.VENDOR_PRODUCT)
        )
        # Validate that vendor product pair is in lowercase
        for items in cls.VENDOR_PRODUCT:
            for vp in items:
                if vp.islower() != True:
                    raise InvalidCheckerError(
                        f"Checker {name} has a VENDOR_PRODUCT string that is not lowercase"
                    )
        # Compile regex
        cls.CONTAINS_PATTERNS = list(map(re.compile, cls.CONTAINS_PATTERNS))
        cls.VERSION_PATTERNS = list(map(re.compile, cls.VERSION_PATTERNS))
        cls.FILENAME_PATTERNS = list(map(re.compile, cls.FILENAME_PATTERNS))
        cls.CONTAINS_PATTERNS.extend(cls.VERSION_PATTERNS)
        # Return the new checker class
        return cls


class Checker(metaclass=CheckerMetaClass):
    CONTAINS_PATTERNS = []
    VERSION_PATTERNS = []
    FILENAME_PATTERNS = []
    VENDOR_PRODUCT = []

    def guess_contains(self, lines):
        for line in lines:
            if any(pattern.search(line) for pattern in self.CONTAINS_PATTERNS):
                return True
        return False

    def get_version(self, lines, filename):
        version_info = dict()

        if any(pattern.search(filename) for pattern in self.FILENAME_PATTERNS):
            version_info["is_or_contains"] = "is"

        if "is_or_contains" not in version_info and self.guess_contains(lines):
            version_info["is_or_contains"] = "contains"

        if "is_or_contains" in version_info:
            version_info["version"] = regex_find(lines, self.VERSION_PATTERNS)

        return version_info
