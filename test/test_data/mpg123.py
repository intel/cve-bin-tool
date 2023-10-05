# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "mpg123", "version": "1.25.10", "version_strings": ["mpg123\n1.25.10"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/m/",
        "package_name": "mpg123-1.31.3-2.fc39.aarch64.rpm",
        "product": "mpg123",
        "version": "1.31.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/m/mpg123/",
        "package_name": "mpg123_1.25.10-2_amd64.deb",
        "product": "mpg123",
        "version": "1.25.10",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "mpg123_1.25.13-2_x86_64.ipk",
        "product": "mpg123",
        "version": "1.25.13",
    },
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "mpg123-1.25.13-r0.apk",
        "product": "mpg123",
        "version": "1.25.13",
    },
]
