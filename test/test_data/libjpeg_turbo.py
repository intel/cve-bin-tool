# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libjpeg-turbo",
        "version": "2.0.1",
        "version_strings": [
            "libjpeg-turbo version 2.0.1",
            "Invalid JPEG file structure: two SOF markers",
        ],
    }
]
package_test_data = [
    {
        "url": "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
        "package_name": "libjpeg-turbo-2.0.2-1.fc30.x86_64.rpm",
        "product": "libjpeg-turbo",
        "version": "2.0.2",
        "other_products": ["libjpeg"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/libj/libjpeg-turbo/",
        "package_name": "libjpeg62-turbo_1.5.1-2_amd64.deb",
        "product": "libjpeg-turbo",
        "version": "1.5.1",
        "other_products": ["libjpeg"],
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.3/packages/x86_64/packages/",
        "package_name": "libjpeg-turbo_2.1.2-1_x86_64.ipk",
        "product": "libjpeg-turbo",
        "version": "2.1.2",
        "other_products": ["libjpeg"],
    },
]
