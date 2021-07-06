# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "python",
        "version": "2.7.0",
        "version_strings": [
            "2.7.0",
            "Internal error in the Python interpreter",
            "Cpython",
            "lib/python2.7",
            "~/anaconda/bin/python",
        ],
    },
    {
        "product": "python",
        "version": "3.7.1",
        "version_strings": [
            "3.7.1",
            "Internal error in the Python interpreter",
            "lib/python3.7",
        ],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org//packages/python3/3.8.2~rc1/1.fc33/aarch64/",
        "package_name": "python3-3.8.2~rc1-1.fc33.aarch64.rpm",
        "product": "python",
        "version": "3.8.2",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/aarch64/os/Packages/p/",
        "package_name": "python3-3.9.0-1.fc33.aarch64.rpm",
        "product": "python",
        "version": "3.9.0",
    },
]
