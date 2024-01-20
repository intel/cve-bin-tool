# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libheif", "version": "1.3.2", "version_strings": ["1.3.2\nheif"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libheif-1.17.5-1.fc40.aarch64.rpm",
        "product": "libheif",
        "version": "1.17.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libh/libheif/",
        "package_name": "libheif1_1.3.2-2~deb10u1_amd64.deb",
        "product": "libheif",
        "version": "1.3.2",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "libheif-1.6.0-r0.apk",
        "product": "libheif",
        "version": "1.6.0",
    },
]
