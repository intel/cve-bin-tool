# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

""" CVE Checkers """
from __future__ import annotations

import collections
import re
import sys

from cve_bin_tool.error_handler import InvalidCheckerError
from cve_bin_tool.util import regex_find

if sys.version_info >= (3, 10):
    from importlib import metadata as importlib_metadata
else:
    import importlib_metadata
if sys.version_info >= (3, 9):
    import importlib.resources as resources
else:
    import importlib_resources as resources

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
    "axel",
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
    "bwm_ng",
    "bzip2",
    "c_ares",
    "capnproto",
    "ceph",
    "chess",
    "chrony",
    "civetweb",
    "clamav",
    "collectd",
    "commons_compress",
    "connman",
    "coreutils",
    "cpio",
    "cronie",
    "cryptsetup",
    "cups",
    "curl",
    "cvs",
    "darkhttpd",
    "dav1d",
    "davfs2",
    "dbus",
    "debianutils",
    "dhclient",
    "dhcpcd",
    "dhcpd",
    "dmidecode",
    "dnsmasq",
    "docker",
    "domoticz",
    "dosfstools",
    "dotnet",
    "dovecot",
    "doxygen",
    "dpkg",
    "dropbear",
    "e2fsprogs",
    "ed",
    "elfutils",
    "enscript",
    "emacs",
    "exfatprogs",
    "exim",
    "exiv2",
    "f2fs_tools",
    "faad2",
    "fastd",
    "ffmpeg",
    "file",
    "firefox",
    "flac",
    "fluidsynth",
    "freeradius",
    "freerdp",
    "fribidi",
    "frr",
    "gawk",
    "gcc",
    "gdal",
    "gdb",
    "gdk_pixbuf",
    "ghostscript",
    "gimp",
    "git",
    "gmp",
    "gnomeshell",
    "gnupg",
    "gnutls",
    "glib",
    "glibc",
    "go",
    "gpgme",
    "gpsd",
    "graphicsmagick",
    "grep",
    "grub2",
    "gstreamer",
    "gupnp",
    "gvfs",
    "gzip",
    "haproxy",
    "harfbuzz",
    "haserl",
    "hdf5",
    "heimdal",
    "hostapd",
    "hunspell",
    "hwloc",
    "i2pd",
    "icecast",
    "icu",
    "iperf3",
    "ipmitool",
    "ipsec_tools",
    "iptables",
    "irssi",
    "iucode_tool",
    "iwd",
    "jack2",
    "jacksondatabind",
    "janus",
    "jasper",
    "jhead",
    "jq",
    "json_c",
    "kbd",
    "keepalived",
    "kerberos",
    "kexectools",
    "kodi",
    "kubernetes",
    "ldns",
    "lftp",
    "libarchive",
    "libass",
    "libbpg",
    "libcoap",
    "libconfuse",
    "libcurl",
    "libdb",
    "libde265",
    "libebml",
    "libevent",
    "libexpat",
    "libgcrypt",
    "libgd",
    "libgit2",
    "libheif",
    "libical",
    "libidn2",
    "libinput",
    "libjpeg",
    "libjpeg_turbo",
    "libksba",
    "liblas",
    "libmatroska",
    "libmemcached",
    "libmicrohttpd",
    "libmodbus",
    "libnss",
    "libopenmpt",
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
    "libtasn1",
    "libtiff",
    "libtomcrypt",
    "libupnp",
    "libuv",
    "libvips",
    "libvirt",
    "libvncserver",
    "libvorbis",
    "libvpx",
    "libxslt",
    "libyaml",
    "lighttpd",
    "linux_kernel",
    "lldpd",
    "logrotate",
    "lrzip",
    "lua",
    "luajit",
    "lxc",
    "lynx",
    "lz4",
    "mailx",
    "mariadb",
    "mbedtls",
    "mdadm",
    "memcached",
    "micropython",
    "minetest",
    "mini_httpd",
    "minicom",
    "minidlna",
    "miniupnpc",
    "miniupnpd",
    "moby",
    "modsecurity",
    "monit",
    "mosquitto",
    "motion",
    "mp4v2",
    "mpg123",
    "mpv",
    "msmtp",
    "mtr",
    "mupdf",
    "mutt",
    "mysql",
    "nano",
    "nasm",
    "nbd",
    "ncurses",
    "neon",
    "nessus",
    "netatalk",
    "netdata",
    "netkit_ftp",
    "netpbm",
    "nettle",
    "nghttp2",
    "nginx",
    "ngircd",
    "nmap",
    "node",
    "ntfs_3g",
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
    "php",
    "picocom",
    "pigz",
    "pixman",
    "png",
    "polarssl_fedora",
    "poppler",
    "postgresql",
    "ppp",
    "privoxy",
    "procps_ng",
    "proftpd",
    "protobuf_c",
    "pspp",
    "pure_ftpd",
    "putty",
    "python",
    "qemu",
    "qpdf",
    "qt",
    "quagga",
    "radare2",
    "radvd",
    "raptor",
    "rauc",
    "rdesktop",
    "readline",
    "rpm",
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
    "sngrep",
    "snort",
    "socat",
    "sofia_sip",
    "speex",
    "spice",
    "sqlite",
    "squashfs",
    "squid",
    "sslh",
    "snapd",
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
    "tar",
    "tcpdump",
    "tcpreplay",
    "terminology",
    "tesseract",
    "thrift",
    "thttpd",
    "thunderbird",
    "timescaledb",
    "tinyproxy",
    "tor",
    "tpm2_tss",
    "traceroute",
    "transmission",
    "trousers",
    "ttyd",
    "twonky_server",
    "u_boot",
    "udisks",
    "unbound",
    "unixodbc",
    "upx",
    "util_linux",
    "varnish",
    "vlc",
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
    "xwayland",
    "yasm",
    "zabbix",
    "zchunk",
    "zeek",
    "zlib",
    "znc",
    "zsh",
    "zstandard",
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


BUILTIN_CHECKERS = {
    checker_path.stem: importlib_metadata.EntryPoint(
        checker_path.stem,
        f'cve_bin_tool.checkers.{checker_path.stem}:{"".join(checker_path.stem.replace("_", " ").title().split())}Checker',
        "cve_bin_tool.checkers",
    )
    for checker_path in resources.files("cve_bin_tool.checkers").iterdir()
    if (checker_path.suffix == ".py" and not checker_path.name.startswith("__"))
}
