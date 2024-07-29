# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "firefox",
        "version": "83.0",
        "version_strings": [r"firefox-83.0"],
    },
]
package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/f/",
        "package_name": "firefox-106.0.4-1.fc38.aarch64.rpm",
        "product": "firefox",
        "version": "106.0.4",
        "other_products": [
            "libjpeg",
            "libjpeg-turbo",
            "libvpx",
            "lz4",
            "rust",
            "sqlite",
        ],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/firefox/",
        "package_name": "firefox_83.0-1_mipsel.deb",
        "product": "firefox",
        "version": "83.0",
        "other_products": ["libjpeg", "libjpeg-turbo", "lz4", "rust", "sqlite"],
    },
]
