# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libpcap",
        "version": "1.10.1",
        "version_strings": ["libpcap version 1.10.1"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libpcap-1.10.1-4.fc37.aarch64.rpm",
        "product": "libpcap",
        "version": "1.10.1",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "libpcap-1.10.1-4.fc37.i686.rpm",
        "product": "libpcap",
        "version": "1.10.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libp/libpcap/",
        "package_name": "libpcap0.8_1.10.0-2_amd64.deb",
        "product": "libpcap",
        "version": "1.10.0",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libp/libpcap/",
        "package_name": "libpcap0.8_1.10.0-2_arm64.deb",
        "product": "libpcap",
        "version": "1.10.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libpcap1_1.9.1-2.1_x86_64.ipk",
        "product": "libpcap",
        "version": "1.9.1",
    },
]
