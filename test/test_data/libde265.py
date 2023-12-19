# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libde265", "version": "1.0.3", "version_strings": ["1.0.3\nde265"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/rpmfusion/free/fedora/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libde265-1.0.14-1.fc40.aarch64.rpm",
        "product": "libde265",
        "version": "1.0.14",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libd/libde265/",
        "package_name": "libde265-0_1.0.3-1+b1_amd64.deb",
        "product": "libde265",
        "version": "1.0.3",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "libde265-1.0.3-r0.apk",
        "product": "libde265",
        "version": "1.0.3",
    },
]
