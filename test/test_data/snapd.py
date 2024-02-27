# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "snapd", "version": "2.56", "version_strings": ["snapd-2.56"]},
]
package_test_data = [
    {
        "url": "https://distrib-coffee.ipsl.jussieu.fr/pub/linux/altlinux/p10/branch/aarch64/RPMS.classic/",
        "package_name": "snapd-2.56-alt1.aarch64.rpm",
        "product": "snapd",
        "version": "2.56",
        "other_products": ["bzip2", "go"],
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/s/snapd/",
        "package_name": "snapd_2.57.6-1+b5_amd64.deb",
        "product": "snapd",
        "version": "2.57.6",
        "other_products": ["bzip2", "go"],
    },
    {
        "url": "https://dl.fedoraproject.org/pub/fedora/linux/updates/38/Everything/aarch64/Packages/s/",
        "package_name": "snapd-2.61.1-0.fc38.aarch64.rpm",
        "product": "snapd",
        "version": "2.61.1",
        "other_products": ["bzip2", "go"],
    },
]
