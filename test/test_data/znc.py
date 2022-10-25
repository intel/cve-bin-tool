# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "znc", "version": "1.8.2", "version_strings": ["znc-1.8.2"]},
    {
        "product": "znc",
        "version": "1.7.4",
        "version_strings": ["1.7.4\n, build: autoconf\n/.znc"],
    },
    {
        "product": "znc",
        "version": "1.7.2",
        "version_strings": ["1.7.2\nDeleting pid file [\nZNC"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/mageia/distrib/cauldron/aarch64/media/core/release/",
        "package_name": "znc-1.8.2-18.mga9.aarch64.rpm",
        "product": "znc",
        "version": "1.8.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/z/znc/",
        "package_name": "znc_1.7.2-3_amd64.deb",
        "product": "znc",
        "version": "1.7.2",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "znc_1.7.4-1_x86_64.ipk",
        "product": "znc",
        "version": "1.7.4",
    },
]
