# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "readline",
        "version": "8.0",
        "version_strings": ["8.0\n_*\\AaIiCcDdPpYyRrSsXx~"],
    },
    {
        "product": "readline",
        "version": "8.2",
        "version_strings": ["libreadline.so.8.2"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/r/",
        "package_name": "readline-8.2-3.fc38.aarch64.rpm",
        "product": "readline",
        "version": "8.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/readline/",
        "package_name": "libreadline7_7.0-5_amd64.deb",
        "product": "readline",
        "version": "7.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "libreadline8_8.0-1_x86_64.ipk",
        "product": "readline",
        "version": "8.0",
    },
]
