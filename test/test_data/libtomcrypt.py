# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libtomcrypt",
        "version": "1.18.2",
        "version_strings": ["LibTomCrypt 1.18.2"],
    },
    {
        "product": "libtomcrypt",
        "version": "1.17",
        "version_strings": ["LibTomCrypt 1.17"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "libtomcrypt-1.18.2-15.fc37.aarch64.rpm",
        "product": "libtomcrypt",
        "version": "1.18.2",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "libtomcrypt-1.18.2-15.fc37.i686.rpm",
        "product": "libtomcrypt",
        "version": "1.18.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libt/libtomcrypt/",
        "package_name": "libtomcrypt0_1.17-6_amd64.deb",
        "product": "libtomcrypt",
        "version": "1.17",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libt/libtomcrypt/",
        "package_name": "libtomcrypt0_1.17-6_armel.deb",
        "product": "libtomcrypt",
        "version": "1.17",
    },
]
