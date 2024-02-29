# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libuv", "version": "1.24.1", "version_strings": ["libuv-v1.24.1"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libuv-1.48.0-1.fc40.aarch64.rpm",
        "product": "libuv",
        "version": "1.48.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libu/libuv1/",
        "package_name": "libuv1_1.24.1-1+deb10u1_amd64.deb",
        "product": "libuv",
        "version": "1.24.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libuv1_1.40.0-2_x86_64.ipk",
        "product": "libuv",
        "version": "1.40.0",
    },
]
