# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libtiff",
        "version": "4.0.2",
        "version_strings": [
            'TIFF directory is missing required \\"StripByteCounts\\" field, calculating from imagelength',
            "LIBTIFF, Version 4.0.2\nCopyright",
        ],
    }
]
package_test_data = [
    {
        "url": "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/30/Everything/x86_64/os/Packages/l/",
        "package_name": "libtiff-4.0.10-4.fc30.i686.rpm",
        "product": "libtiff",
        "version": "4.0.10",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libtiff-4.0.3-35.el7.x86_64.rpm",
        "product": "libtiff",
        "version": "4.0.3",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/t/tiff/",
        "package_name": "libtiff5_4.2.0-1+deb11u4_amd64.deb",
        "product": "libtiff",
        "version": "4.2.0",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libtiff_4.1.0-1_x86_64.ipk",
        "product": "libtiff",
        "version": "4.1.0",
    },
]
