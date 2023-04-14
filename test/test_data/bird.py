# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "bird", "version": "2.0.10", "version_strings": ["BIRD 2.0.10"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/b/",
        "package_name": "bird-2.0.10-3.fc37.aarch64.rpm",
        "product": "bird",
        "version": "2.0.10",
    },
    {
        "url": "http://rpmfind.net/linux/fedora-secondary/development/rawhide/Everything/ppc64le/os/Packages/b/",
        "package_name": "bird-2.0.10-3.fc37.ppc64le.rpm",
        "product": "bird",
        "version": "2.0.10",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/b/bird/",
        "package_name": "bird_1.6.3-2+deb9u1_arm64.deb",
        "product": "bird",
        "version": "1.6.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.0/packages/x86_64/routing/",
        "package_name": "bird1-ipv4_1.6.8-2_x86_64.ipk",
        "product": "bird",
        "version": "1.6.8",
    },
]
