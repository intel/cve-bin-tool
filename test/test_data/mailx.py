# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "mailx", "version": "12.5", "version_strings": ["mailx 12.5"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/m/",
        "package_name": "mailx-12.5-42.fc37.aarch64.rpm",
        "product": "mailx",
        "version": "12.5",
    },
    {
        "url": "http://rpmfind.net/linux/fedora-secondary/development/rawhide/Everything/ppc64le/os/Packages/m/",
        "package_name": "mailx-12.5-42.fc37.ppc64le.rpm",
        "product": "mailx",
        "version": "12.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/h/heirloom-mailx/",
        "package_name": "heirloom-mailx_12.5-4_amd64.deb",
        "product": "mailx",
        "version": "12.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/h/heirloom-mailx/",
        "package_name": "heirloom-mailx_12.5-4_armel.deb",
        "product": "mailx",
        "version": "12.5",
    },
]
