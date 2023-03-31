# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "neon", "version": "0.32.3", "version_strings": ["neon 0.32.3"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/n/",
        "package_name": "neon-0.32.3-1.fc38.aarch64.rpm",
        "product": "neon",
        "version": "0.32.3",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/n/",
        "package_name": "neon-0.32.3-1.fc38.i686.rpm",
        "product": "neon",
        "version": "0.32.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/neon27/",
        "package_name": "libneon27_0.30.1-1_amd64.deb",
        "product": "neon",
        "version": "0.30.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libneon_0.30.2-4_x86_64.ipk",
        "product": "neon",
        "version": "0.30.2",
    },
]
