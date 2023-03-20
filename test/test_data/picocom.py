# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "picocom", "version": "1.7", "version_strings": ["picocom v%s\n1.7"]},
    {"product": "picocom", "version": "3.1", "version_strings": ["3.1\npicocom v%s"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/p/",
        "package_name": "picocom-3.1-13.fc38.aarch64.rpm",
        "product": "picocom",
        "version": "3.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/picocom/",
        "package_name": "picocom_1.7-1_amd64.deb",
        "product": "picocom",
        "version": "1.7",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "picocom_3.1-3_x86_64.ipk",
        "product": "picocom",
        "version": "3.1",
    },
]
