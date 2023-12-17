# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "mbed_tls",
        "version": "2.16.0",
        "version_strings": ["mbed TLS 2.16.0"],
    },
    {
        "product": "mbed_tls",
        "version": "2.28.5",
        "version_strings": ["Mbed TLS 2.28.5"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/m/",
        "package_name": "mbedtls-2.28.5-1.fc40.aarch64.rpm",
        "product": "mbed_tls",
        "version": "2.28.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/m/mbedtls/",
        "package_name": "libmbedcrypto3_2.16.0-1_amd64.deb",
        "product": "mbed_tls",
        "version": "2.16.0",
    },
    {
        "url": "https://dl-cdn.alpinelinux.org/alpine/v3.11/main/x86_64/",
        "package_name": "mbedtls-2.16.9-r0.apk",
        "product": "mbed_tls",
        "version": "2.16.9",
    },
]
