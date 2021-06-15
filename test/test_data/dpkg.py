# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "dpkg",
        "version": "1.20.9",
        "version_strings": [
            "dpkg-1.20.9",
            "dpkg-deb-1.20.9",
            "dpkg-query-1.20.9",
            "dpkg-divert-1.20.9",
        ],
    },
    {
        "product": "dpkg",
        "version": "1.18.25",
        "version_strings": [
            "dpkg-1.18.25",
            "dpkg-deb-1.18.25",
            "dpkg-query-1.18.25",
            "dpkg-divert-1.18.25",
        ],
    },
]
package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/aarch64/os/Packages/d/",
        "package_name": "dpkg-1.20.9-2.fc35.aarch64.rpm",
        "product": "dpkg",
        "version": "1.20.9",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/epel/8/Everything/aarch64/Packages/d/",
        "package_name": "dpkg-1.18.25-12.el8.aarch64.rpm",
        "product": "dpkg",
        "version": "1.18.25",
    },
]
