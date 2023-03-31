# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "free_range_routing",
        "version": "8.4.2",
        "version_strings": ["FRR (version 8.4.2)"],
    },
    {
        "product": "free_range_routing",
        "version": "7.5",
        "version_strings": ["7.5\nbabeld daemon"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/f/",
        "package_name": "frr-8.4.2-2.fc38.aarch64.rpm",
        "product": "free_range_routing",
        "version": "8.4.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/f/frr/",
        "package_name": "frr_6.0.2-2+deb10u1_amd64.deb",
        "product": "free_range_routing",
        "version": "6.0.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/21.02.5/packages/x86_64/packages/",
        "package_name": "frr-babeld_7.5-4_x86_64.ipk",
        "product": "free_range_routing",
        "version": "7.5",
    },
]
