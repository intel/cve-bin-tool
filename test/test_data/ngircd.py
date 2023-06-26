# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "ngircd", "version": "26.1", "version_strings": ["26.1\nngIRCd"]},
    {
        "product": "ngircd",
        "version": "26.1",
        "version_strings": ["ngIRCd\n%s %s-%s\n26.1"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/n/",
        "package_name": "ngircd-26.1-8.fc38.aarch64.rpm",
        "product": "ngircd",
        "version": "26.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/ngircd/",
        "package_name": "ngircd_26.1-1_amd64.deb",
        "product": "ngircd",
        "version": "26.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.0/packages/x86_64/packages/",
        "package_name": "ngircd_26.1-1_x86_64.ipk",
        "product": "ngircd",
        "version": "26.1",
    },
]
