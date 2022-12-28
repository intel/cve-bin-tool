# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "sysstat",
        "version": "11.0.1",
        "version_strings": ["sysstat version %s\n11.0.1"],
    },
    {
        "product": "sysstat",
        "version": "12.0.5",
        "version_strings": ["12.0.5\nsysstat version %s"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/s/",
        "package_name": "sysstat-12.7.1-1.fc38.aarch64.rpm",
        "product": "sysstat",
        "version": "12.7.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/s/sysstat/",
        "package_name": "sysstat_11.0.1-1_amd64.deb",
        "product": "sysstat",
        "version": "11.0.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "sysstat_12.0.5-1_x86_64.ipk",
        "product": "sysstat",
        "version": "12.0.5",
    },
]
