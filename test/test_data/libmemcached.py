# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libmemcached",
        "version": "1.0.18",
        "version_strings": ["memcp-1.0.18"],
    },
    {
        "product": "libmemcached",
        "version": "1.0.18",
        "version_strings": ["1.0.18\nversion\nlibmemcached"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/releases/34/Everything/aarch64/os/Packages/l/",
        "package_name": "libmemcached-1.0.18-22.fc34.aarch64.rpm",
        "product": "libmemcached",
        "version": "1.0.18",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libm/libmemcached/",
        "package_name": "libmemcached11_1.0.18-4.1_amd64.deb",
        "product": "libmemcached",
        "version": "1.0.18",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libm/libmemcached/",
        "package_name": "libmemcached11_1.1.4-1_arm64.deb",
        "product": "libmemcached",
        "version": "1.1.4",
    },
]
