# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "lynx",
        "version": "2.9.0dev.10",
        "version_strings": ["2.9.0dev.10\nLynx"],
    },
    {
        "product": "lynx",
        "version": "2.8.9rel.1",
        "version_strings": ["https://lynx.invisible-island.net/\n2.8.9rel.1"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "lynx-2.9.0-dev.10.2.fc37.1.aarch64.rpm",
        "product": "lynx",
        "version": "2.9.0dev.10",
    },
    {
        "url": "http://rpmfind.net/linux/fedora-secondary/development/rawhide/Everything/ppc64le/os/Packages/l/",
        "package_name": "lynx-2.9.0-dev.10.2.fc37.1.ppc64le.rpm",
        "product": "lynx",
        "version": "2.9.0dev.10",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/l/lynx/",
        "package_name": "lynx_2.8.9dev11-1_arm64.deb",
        "product": "lynx",
        "version": "2.8.9dev.11",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "lynx_2.8.9rel.1-1_x86_64.ipk",
        "product": "lynx",
        "version": "2.8.9rel.1",
    },
]
