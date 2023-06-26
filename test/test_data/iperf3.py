# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "iperf3", "version": "3.11", "version_strings": ["iperf 3.11"]},
    {"product": "iperf3", "version": "3.0.7", "version_strings": ["iperf 3.0.7"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/i/",
        "package_name": "iperf3-3.11-3.fc38.aarch64.rpm",
        "product": "iperf3",
        "version": "3.11",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/i/",
        "package_name": "iperf3-3.11-3.fc38.i686.rpm",
        "product": "iperf3",
        "version": "3.11",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/iperf3/",
        "package_name": "libiperf0_3.0.7-1_amd64.deb",
        "product": "iperf3",
        "version": "3.0.7",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "iperf3_3.7-1_x86_64.ipk",
        "product": "iperf3",
        "version": "3.7",
    },
]
