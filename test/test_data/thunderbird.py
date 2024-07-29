# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "thunderbird",
        "version": "102.5.1",
        "version_strings": [r'"name":"thunderbird","version":"102.5.1'],
    },
]
package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/t/",
        "package_name": "thunderbird-102.5.1-1.fc38.aarch64.rpm",
        "product": "thunderbird",
        "version": "102.5.1",
        "other_products": [
            "libjpeg",
            "libjpeg-turbo",
            "libvpx",
            "lz4",
            "rust",
            "sqlite",
        ],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/thunderbird/",
        "package_name": "thunderbird_52.8.0-1~deb8u1_amd64.deb",
        "product": "thunderbird",
        "version": "52.8.0",
        "other_products": [
            "libjpeg",
            "libjpeg-turbo",
            "libvorbis",
            "libvpx",
            "network_security_services",
            "sqlite",
        ],
    },
]
