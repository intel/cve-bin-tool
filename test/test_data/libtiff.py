# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libtiff",
        "version": "4.0.2",
        "version_strings": [
            'TIFF directory is missing required \\"StripByteCounts\\" field, calculating from imagelength',
            "LIBTIFF, Version 4.0.2",
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
]
