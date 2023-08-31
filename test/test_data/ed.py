# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "ed", "version": "1.15", "version_strings": ["1.15\nGNU ed"]},
    {"product": "ed", "version": "1.19", "version_strings": ["ed.html\n1.19"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/e/",
        "package_name": "ed-1.19-4.fc39.aarch64.rpm",
        "product": "ed",
        "version": "1.19",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/e/ed/",
        "package_name": "ed_1.15-1_amd64.deb",
        "product": "ed",
        "version": "1.15",
    },
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "ed-1.15-r0.apk",
        "product": "ed",
        "version": "1.15",
    },
]
