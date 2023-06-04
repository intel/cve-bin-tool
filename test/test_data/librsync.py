# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "librsync", "version": "2.3.2", "version_strings": ["librsync 2.3.2"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/l/",
        "package_name": "librsync-2.3.2-4.fc37.aarch64.rpm",
        "product": "librsync",
        "version": "2.3.2",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "librsync-2.3.2-4.fc37.i686.rpm",
        "product": "librsync",
        "version": "2.3.2",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libr/librsync/",
        "package_name": "librsync1_0.9.7-10+b1_amd64.deb",
        "product": "librsync",
        "version": "0.9.7",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libr/librsync/",
        "package_name": "librsync1_0.9.7-10+b1_arm64.deb",
        "product": "librsync",
        "version": "0.9.7",
    },
]
