# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "c-ares", "version": "1.17.2", "version_strings": ["c-ares-1.17.2"]},
    {
        "product": "c-ares",
        "version": "1.10.0",
        "version_strings": [
            "c-ares library initialization not yet performed\nCould not find GetNetworkParams function\n1.10.0"
        ],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/c/",
        "package_name": "c-ares-1.17.2-3.fc37.aarch64.rpm",
        "product": "c-ares",
        "version": "1.17.2",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/c/",
        "package_name": "c-ares-1.17.2-3.fc37.i686.rpm",
        "product": "c-ares",
        "version": "1.17.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/c-ares/",
        "package_name": "libc-ares2_1.10.0-2%2Bdeb8u2_amd64.deb",
        "product": "c-ares",
        "version": "1.10.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libcares_1.15.0-5_x86_64.ipk",
        "product": "c-ares",
        "version": "1.15.0",
    },
]
