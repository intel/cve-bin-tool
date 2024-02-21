# Copyright (C) 2023 SCHUTZWERK GmbH
# SPDX-License-Identifier: GPL-3.0-or-later


mapping_test_data = [
    {
        "product": "dosfstools",
        "version": "4.2",
        "version_strings": ["mkfs.fat 4.2 (2021-01-31)"],
    }
]

package_test_data = [
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/d/dosfstools/",
        "package_name": "dosfstools_4.2-1_amd64.deb",
        "product": "dosfstools",
        "version": "4.2",
    },
    {
        "url": "http://de.archive.ubuntu.com/ubuntu/pool/main/d/dosfstools/",
        "package_name": "dosfstools_4.2-1build3_amd64.deb",
        "product": "dosfstools",
        "version": "4.2",
    },
    {
        "url": "https://rpmfind.net/linux/fedora/linux/releases/38/Everything/x86_64/os/Packages/d/",
        "package_name": "dosfstools-4.2-6.fc38.x86_64.rpm",
        "product": "dosfstools",
        "version": "4.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.5/packages/x86_64/packages/",
        "package_name": "dosfstools_4.2-2_x86_64.ipk",
        "product": "dosfstools",
        "version": "4.2",
    },
]
