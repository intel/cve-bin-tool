# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "libvips", "version": "8.7.4", "version_strings": ["8.7.4\nlibvips"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/v/",
        "package_name": "vips-8.15.1-2.fc40.aarch64.rpm",
        "product": "libvips",
        "version": "8.15.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/v/vips/",
        "package_name": "libvips42_8.7.4-1%2Bdeb10u1_amd64.deb",
        "product": "libvips",
        "version": "8.7.4",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "vips_8.7.4-3_x86_64.ipk",
        "product": "libvips",
        "version": "8.7.4",
    },
]
