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
    "apparmor",
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
    "bluez",
    "boinc",
    "botan",
    "bro",
    "bubblewrap",
    "busybox",
    "bzip2",
    "c_ares",
    "capnproto",
    "ceph",
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
    "dhclient",
    "dhcpcd",
    "dhcpd",
    "dnsmasq",
    "domoticz",
    "dovecot",
    "doxygen",
    "dpkg",
    "dropbear",
    "e2fsprogs",
    "elfutils",
    "enscript",
    "exim",
    "exiv2",
    "expat",
    "f2fs_tools",
    "faad2",
    "fastd",
    "ffmpeg",
    "file",
    "firefox",
    "flac",
    "freeradius",
    "freerdp",
    "fribidi",
    "frr",
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
    "harfbuzz",
    "haserl",
    "hdf5",
    "hostapd",
    "hunspell",
    "i2pd",
    "icecast",
    "icu",
    "iperf3",
    "ipmitool",
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
    "kodi",
    "kubernetes",
    "lftp",
    "libarchive",
    "libass",
    "libbpg",
    "libconfuse",
    "libdb",
    "libebml",
    "libgcrypt",
    "libgit2",
    "libical",
    "libidn2",
    "libinput",
    "libjpeg",
    "libjpeg_turbo",
    "libksba",
    "liblas",
    "libmatroska",
    "libmemcached",
    "libnss",
    "libpcap",
    "libraw",
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
    "linux_kernel",
    "lldpd",
    "logrotate",
    "lua",
    "luajit",
    "lxc",
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
    "modsecurity",
    "mosquitto",
    "motion",
    "mpv",
    "msmtp",
    "mtr",
    "mutt",
    "mysql",
    "nano",
    "nasm",
    "nbd",
    "ncurses",
    "neon",
    "nessus",
    "netatalk",
    "netkit_ftp",
    "netpbm",
    "nettle",
    "nghttp2",
    "nginx",
    "nmap",
    "node",
    "ntp",
    "ntpsec",
    "open_iscsi",
    "open_vm_tools",
    "openafs",
    "opencv",
    "openjpeg",
    "openldap",
    "opensc",
    "openssh",
    "openssl",
    "openswan",
    "openvpn",
    "p7zip",
    "pango",
    "patch",
    "pcre",
    "pcre2",
    "pcsc_lite",
    "perl",
    "picocom",
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
    "qemu",
    "qt",
    "quagga",
    "radare2",
    "radvd",
    "raptor",
    "rauc",
    "rdesktop",
    "rtl_433",
    "rtmpdump",
    "rsync",
    "rsyslog",
    "runc",
    "rust",
    "samba",
    "sane_backends",
    "sdl",
    "seahorse",
    "shadowsocks_libev",
    "snort",
    "sofia_sip",
    "speex",
    "spice",
    "sqlite",
    "squashfs",
    "squid",
    "sslh",
    "stellarium",
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
    "tcpreplay",
    "thrift",
    "thttpd",
    "thunderbird",
    "timescaledb",
    "tinyproxy",
    "tor",
    "tpm2_tss",
    "transmission",
    "trousers",
    "u_boot",
    "unbound",
    "unixodbc",
    "upx",
    "util_linux",
    "varnish",
    "vorbis_tools",
    "vsftpd",
    "vim",
    "webkitgtk",
    "wget",
    "wireshark",
    "wolfssl",
    "wpa_supplicant",
    "xerces",
    "xml2",
    "xscreensaver",
    "yasm",
    "zabbix",
    "zeek",
    "zlib",
    "znc",
    "zsh",
]

VendorProductPair = collections.namedtuple("VendorProductPair", ["vendor", "product"])


class CheckerMetaClass(type):
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
        if cls.IGNORE_PATTERNS is None:
            cls.IGNORE_PATTERNS = []
        else:
            cls.IGNORE_PATTERNS = list(map(re.compile, cls.IGNORE_PATTERNS))
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
    IGNORE_PATTERNS: list[str] = []

    def guess_contains(self, lines):
        if any(pattern.search(lines) for pattern in self.CONTAINS_PATTERNS):
            return True
        return False

    def get_version(self, lines, filename):
        version_info = dict()

        if any(pattern.match(filename) for pattern in self.FILENAME_PATTERNS):
            version_info["is_or_contains"] = "is"

        if "is_or_contains" not in version_info and self.guess_contains(lines):
            version_info["is_or_contains"] = "contains"

        if "is_or_contains" in version_info:
            version_info["version"] = regex_find(
                lines, self.VERSION_PATTERNS, self.IGNORE_PATTERNS
            )

        return version_info
