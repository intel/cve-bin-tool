# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "inet_wireless_daemon",
        "version": "2.11",
        "version_strings": ["iwctl version 2.11"],
    },
    {
        "product": "inet_wireless_daemon",
        "version": "0.14",
        "version_strings": ["0.14\nIWD version %s"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/i/",
        "package_name": "iwd-2.11-1.fc40.aarch64.rpm",
        "product": "inet_wireless_daemon",
        "version": "2.11",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/i/iwd/",
        "package_name": "iwd_0.14-2_amd64.deb",
        "product": "inet_wireless_daemon",
        "version": "0.14",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/community/x86_64/",
        "package_name": "iwd-1.2-r1.apk",
        "product": "inet_wireless_daemon",
        "version": "1.2",
    },
]
