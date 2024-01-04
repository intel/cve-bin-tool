# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "zstandard",
        "version": "1.4.0",
        "version_strings": ["Frame requires too much memory for decoding/n1.4.0"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libzstd-1.5.2-3.fc37.aarch64.rpm",
        "product": "zstandard",
        "version": "1.5.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libz/libzstd/",
        "package_name": "libzstd1_1.3.8+dfsg-3+deb10u2_amd64.deb",
        "product": "zstandard",
        "version": "1.3.8",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libzstd_1.4.5-2_x86_64.ipk",
        "product": "zstandard",
        "version": "1.4.5",
    },
]
