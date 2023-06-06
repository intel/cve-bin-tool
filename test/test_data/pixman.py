# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "pixman",
        "version": "0.38.4",
        "version_strings": ["0.38.4\npixman-access.c"],
    },
    {
        "product": "pixman",
        "version": "0.42.2",
        "version_strings": ["pixman-access.c\n0.42.2"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/p/",
        "package_name": "pixman-0.42.2-1.fc39.aarch64.rpm",
        "product": "pixman",
        "version": "0.42.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/pixman/",
        "package_name": "libpixman-1-0_0.36.0-1_amd64.deb",
        "product": "pixman",
        "version": "0.36.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "pixman_0.38.4-1_x86_64.ipk",
        "product": "pixman",
        "version": "0.38.4",
    },
]
