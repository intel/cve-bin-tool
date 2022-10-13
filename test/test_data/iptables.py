# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "iptables", "version": "1.8.8", "version_strings": ["1.8.8\niptables"]},
    {
        "product": "iptables",
        "version": "1.4.3.2",
        "version_strings": ["iptables-save v%s on %s\n1.4.3.2"],
    },
    {
        "product": "iptables",
        "version": "1.4.13",
        "version_strings": ["iptables-1.4.13"],
    },
    {
        "product": "iptables",
        "version": "1.8.8",
        "version_strings": ["iptables-rules>\nverbose\ncombine\nhelp\n1.8.8"],
    },
    {
        "product": "iptables",
        "version": "1.6.2",
        "version_strings": [
            "iptables-rules>\n%s: line %u failed\nverbose\ncombine\nhelp\n1.6.2"
        ],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "iptables-1.8.8-2.2.aarch64.rpm",
        "product": "iptables",
        "version": "1.8.8",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "iptables-1.8.8-2.2.armv6hl.rpm",
        "product": "iptables",
        "version": "1.8.8",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/iptables/",
        "package_name": "iptables-nftables-compat_1.6.2-1.1~bpo9+1_i386.deb",
        "product": "iptables",
        "version": "1.6.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/iptables/",
        "package_name": "iptables-nftables-compat_1.6.2-1.1~bpo9+1_mips.deb",
        "product": "iptables",
        "version": "1.6.2",
    },
]
