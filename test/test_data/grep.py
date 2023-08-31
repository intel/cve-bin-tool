# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "grep", "version": "3.3", "version_strings": ["3.3\nGNU grep"]},
    {"product": "grep", "version": "3.11", "version_strings": ["grep-3.11"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/g/",
        "package_name": "grep-3.11-5.fc40.aarch64.rpm",
        "product": "grep",
        "version": "3.11",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/grep/",
        "package_name": "grep_3.3-1_amd64.deb",
        "product": "grep",
        "version": "3.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "grep_3.3-1_x86_64.ipk",
        "product": "grep",
        "version": "3.3",
    },
]
