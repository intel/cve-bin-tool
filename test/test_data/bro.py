# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "bro", "version": "2.4.1", "version_strings": ["bro-2.4.1"]},
    {"product": "bro", "version": "2.5", "version_strings": ["bro-2.5"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/epel/7/aarch64/Packages/b/",
        "package_name": "bro-2.4.1-3.el7.aarch64.rpm",
        "product": "bro",
        "version": "2.4.1",
        "other_products": ["sqlite"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/b/bro/",
        "package_name": "bro_2.5-1_amd64.deb",
        "product": "bro",
        "version": "2.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/b/bro/",
        "package_name": "bro_2.5.5-1+deb10u1_arm64.deb",
        "product": "bro",
        "version": "2.5.5",
    },
]
