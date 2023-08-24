# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "dav1d", "version": "0.7.1", "version_strings": ["0.7.1\ndav1d"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/d/",
        "package_name": "dav1d-1.2.1-2.fc39.aarch64.rpm",
        "product": "dav1d",
        "version": "1.2.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/d/dav1d/",
        "package_name": "dav1d_0.7.1-3_amd64.deb",
        "product": "dav1d",
        "version": "0.7.1",
    },
    {
        "url": "https://eu.mirror.archlinuxarm.org/aarch64/extra/",
        "package_name": "dav1d-1.2.1-1-aarch64.pkg.tar.xz",
        "product": "dav1d",
        "version": "1.2.1",
        "other_products": ["gcc"],
    },
]
