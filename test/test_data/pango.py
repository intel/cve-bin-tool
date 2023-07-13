# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "pango",
        "version": "1.40.5",
        "version_strings": ["1.40.5\n/etc/pango"],
    },
    {
        "product": "pango",
        "version": "1.40.5",
        "version_strings": ["1.40.5\nPango version"],
    },
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/p/",
        "package_name": "pango-1.50.11-1.fc38.aarch64.rpm",
        "product": "pango",
        "version": "1.50.11",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/p/",
        "package_name": "pango-1.50.11-1.fc38.i686.rpm",
        "product": "pango",
        "version": "1.50.11",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/pango1.0/",
        "package_name": "libpango-1.0-0_1.40.5-1_arm64.deb",
        "product": "pango",
        "version": "1.40.5",
    },
]
