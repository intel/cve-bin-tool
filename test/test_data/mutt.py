# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "mutt",
        "version": "2.2.7",
        "version_strings": ["muttrc-2.2.7"],
    },
    {
        "product": "mutt",
        "version": "1.5.23",
        "version_strings": ["1.5.23\nMutt"],
    },
    {
        "product": "mutt",
        "version": "1.5.23",
        "version_strings": ["Mutt %s (%s)\n1.5.23"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/aarch64/tumbleweed/repo/oss/aarch64/",
        "package_name": "mutt-2.2.7-2.1.aarch64.rpm",
        "product": "mutt",
        "version": "2.2.7",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/ports/armv6hl/tumbleweed/repo/oss/armv6hl/",
        "package_name": "mutt-2.2.7-2.1.armv6hl.rpm",
        "product": "mutt",
        "version": "2.2.7",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/m/mutt/",
        "package_name": "mutt-patched_1.5.23-3_amd64.deb",
        "product": "mutt",
        "version": "1.5.23",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/m/mutt/",
        "package_name": "mutt-patched_1.5.23-3_armel.deb",
        "product": "mutt",
        "version": "1.5.23",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "mutt_1.12.0-1_x86_64.ipk",
        "product": "mutt",
        "version": "1.12.0",
    },
]
