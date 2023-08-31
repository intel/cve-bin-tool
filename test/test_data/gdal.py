# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "gdal", "version": "2.4.0", "version_strings": ["gdal-2.4.0"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/g/",
        "package_name": "gdal-3.7.1-6.fc40.aarch64.rpm",
        "product": "gdal",
        "version": "3.7.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gdal/",
        "package_name": "libgdal20_2.4.0+dfsg-1+b1_amd64.deb",
        "product": "gdal",
        "version": "2.4.0",
        "other_products": ["libtiff"],
    },
]
