# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "go", "version": "1.11.6", "version_strings": ["go1.11.6"]}
]
package_test_data = [
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/golang-1.11/",
        "package_name": "golang-1.11-go_1.11.6-1+deb10u4_amd64.deb",
        "product": "go",
        "version": "1.11.6",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "golang_1.13.15-1_x86_64.ipk",
        "product": "go",
        "version": "1.13.15",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/community/x86_64/",
        "package_name": "go-1.13.13-r0.apk",
        "product": "go",
        "version": "1.13.13",
    },
]
