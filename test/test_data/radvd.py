# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "router_advertisement_daemon",
        "version": "1.9.1",
        "version_strings": ["1.9.1\nVersion: %s\nCompiled in settings:\n"],
    },
    {
        "product": "router_advertisement_daemon",
        "version": "2.19",
        "version_strings": ["Version: %s\n2.19\nCompiled in settings:\n"],
    },
]
package_test_data = [
    {
        "url": "https://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/r/",
        "package_name": "radvd-2.19-7.fc38.aarch64.rpm",
        "product": "router_advertisement_daemon",
        "version": "2.19",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/radvd/",
        "package_name": "radvd_1.9.1-1.3_amd64.deb",
        "product": "router_advertisement_daemon",
        "version": "1.9.1",
    },
]
