# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" CVE Checkers """
from __future__ import annotations

import collections
import re

from cve_bin_tool.error_handler import InvalidCheckerError
from cve_bin_tool.util import regex_find

__all__ = [
    "Checker",
    "VendorProductPair",
    "accountsservice",
    "acpid",
    "apache_http_server",
    "apcupsd",
    "asn1c",
    "assimp",
    "asterisk",
    "atftp",
    "avahi",
    "bash",
    "bind",
    "binutils",
    "bird",
    "bison",
    "boinc",
    "bolt",
    "bro",
    "bubblewrap",
    "busybox",
    "bzip2",
    "c_ares",
    "chess",
    "chrony",
    "clamav",
    "collectd",
    "commons_compress",
    "connman",
    "cronie",
    "cryptsetup",
    "cups",
    "curl",
    "cvs",
    "darkhttpd",
    "davfs2",
    "dbus",
    "dhcpcd",
    "dnsmasq",
    "domoticz",
    "dovecot",
    "dpkg",
    "e2fsprogs",
    "elfutils",
    "enscript",
    "exim",
    "exiv2",
    "expat",
    "fastd",
    "ffmpeg",
    "file",
    "firefox",
    "freeradius",
    "freerdp",
    "fribidi",
    "ftp",
    "gcc",
    "gdb",
    "gimp",
    "git",
    "gmp",
    "gnomeshell",
    "gnupg",
    "gnutls",
    "glib",
    "glibc",
    "gpgme",
    "gpsd",
    "graphicsmagick",
    "grub2",
    "gstreamer",
    "gupnp",
    "gvfs",
    "haproxy",
    "haserl",
    "hdf5",
    "hostapd",
    "hunspell",
    "i2pd",
    "icecast",
    "icu",
    "iperf3",
    "ipsec_tools",
    "iptables",
    "irssi",
    "iucode_tool",
    "jack2",
    "jacksondatabind",
    "janus",
    "jhead",
    "json_c",
    "kbd",
    "keepalived",
    "kerberos",
    "kexectools",
    "lftp",
    "libarchive",
    "libbpg",
    "libconfuse",
    "libdb",
    "libebml",
    "libgcrypt",
    "libgit2",
    "libical",
    "libinput",
    "libjpeg",
    "libjpeg_turbo",
    "libksba",
    "liblas",
    "libnss",
    "libpcap",
    "librsvg",
    "librsync",
    "libsamplerate",
    "libseccomp",
    "libsndfile",
    "libsolv",
    "libsoup",
    "libsrtp",
    "libssh",
    "libssh2",
    "libtiff",
    "libtomcrypt",
    "libupnp",
    "libvirt",
    "libvncserver",
    "libvorbis",
    "libxslt",
    "lighttpd",
    "lldpd",
    "logrotate",
    "lua",
    "luajit",
    "lynx",
    "lz4",
    "mailx",
    "mariadb",
    "mdadm",
    "memcached",
    "minicom",
    "minidlna",
    "miniupnpc",
    "miniupnpd",
    "mosquitto",
    "motion",
    "mpv",
    "mtr",
    "mutt",
    "mysql",
    "nano",
    "nbd",
    "ncurses",
    "neon",
    "nessus",
    "netatalk",
    "netpbm",
    "nettle",
    "nghttp2",
    "nginx",
    "nmap",
    "node",
    "ntp",
    "ntpsec",
    "open_vm_tools",
    "openafs",
    "opencv",
    "openjpeg",
    "openldap",
    "openssh",
    "openssl",
    "openswan",
    "openvpn",
    "p7zip",
    "pango",
    "patch",
    "pcsc_lite",
    "perl",
    "pigz",
    "png",
    "polarssl_fedora",
    "poppler",
    "postgresql",
    "ppp",
    "privoxy",
    "procps_ng",
    "proftpd",
    "pspp",
    "pure_ftpd",
    "putty",
    "python",
    "qt",
    "quagga",
    "radare2",
    "radvd",
    "rdesktop",
    "rtl_433",
    "rsync",
    "rsyslog",
    "rust",
    "samba",
    "sane_backends",
    "seahorse",
    "shadowsocks_libev",
    "snort",
    "sofia_sip",
    "spice",
    "sqlite",
    "squashfs",
    "squid",
    "strongswan",
    "stunnel",
    "subversion",
    "sudo",
    "suricata",
    "sylpheed",
    "syslogng",
    "sysstat",
    "systemd",
    "tcpdump",
    "thrift",
    "thttpd",
    "timescaledb",
    "tinyproxy",
    "tor",
    "tpm2_tss",
    "transmission",
    "trousers",
    "unbound",
    "unixodbc",
    "upx",
    "util_linux",
    "varnish",
    "vsftpd",
    "webkitgtk",
    "wget",
    "wireshark",
    "wolfssl",
    "wpa_supplicant",
    "xerces",
    "xml2",
    "xscreensaver",
    "zeek",
    "zlib",
    "znc",
    "zsh",
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
                if not vp.islower():
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
    CONTAINS_PATTERNS: list[str] = []
    VERSION_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VENDOR_PRODUCT: list[tuple[str, str]] = []

    def guess_contains(self, lines):
        if any(pattern.search(lines) for pattern in self.CONTAINS_PATTERNS):
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
