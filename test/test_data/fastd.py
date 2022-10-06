# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "fastd", "version": "22", "version_strings": ["fastd v22"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/f/",
        "package_name": "fastd-22-7.fc37.aarch64.rpm",
        "product": "fastd",
        "version": "22",
    },
    {
        "url": "http://rpmfind.net/linux/fedora-secondary/development/rawhide/Everything/ppc64le/os/Packages/f/",
        "package_name": "fastd-22-7.fc37.ppc64le.rpm",
        "product": "fastd",
        "version": "22",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/fastd/",
        "package_name": "fastd_18-2+b1_amd64.deb",
        "product": "fastd",
        "version": "18",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/fastd/",
        "package_name": "fastd_18-2+b1_arm64.deb",
        "product": "fastd",
        "version": "18",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "fastd_18-5_x86_64.ipk",
        "product": "fastd",
        "version": "18",
    },
]
