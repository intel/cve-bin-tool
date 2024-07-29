# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libevent",
        "version": "2.0.21",
        "version_strings": ["2.0.21-stable\nlibevent using:"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libevent-2.1.12-7.fc37.aarch64.rpm",
        "product": "libevent",
        "version": "2.1.12",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libe/libevent/",
        "package_name": "libevent-2.0-5_2.0.21-stable-3_amd64.deb",
        "product": "libevent",
        "version": "2.0.21",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libevent2-7_2.1.11-1_x86_64.ipk",
        "product": "libevent",
        "version": "2.1.11",
    },
]
