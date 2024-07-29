# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "php", "version": "7.3.31", "version_strings": ["PHP/7.3.31"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/updates/39/Everything/aarch64/Packages/p/",
        "package_name": "php-cli-8.2.13-1.fc39.aarch64.rpm",
        "product": "php",
        "version": "8.2.13",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/php7.3/",
        "package_name": "libphp7.3-embed_7.3.31-1~deb10u1_amd64.deb",
        "product": "php",
        "version": "7.3.31",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "php7-cli_7.2.34-4_x86_64.ipk",
        "product": "php",
        "version": "7.2.34",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/community/x86_64/",
        "package_name": "php7-7.3.22-r0.apk",
        "product": "php",
        "version": "7.3.22",
    },
]
