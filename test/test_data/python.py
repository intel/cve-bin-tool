# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "python",
        "version": "2.7.0",
        "version_strings": [
            "2.7.0\nPython %s",
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
            "pymalloc_debug\n3.7.1",
            "Internal error in the Python interpreter",
            "lib/python3.7",
        ],
    },
    {
        "product": "python",
        "version": "3.10.9",
        "version_strings": ["3.10.9\n%.80s (%.80s) %.80s"],
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
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/python2.7/",
        "package_name": "python2.7-minimal_2.7.13-2+deb9u3_amd64.deb",
        "product": "python",
        "version": "2.7.13",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/python3.11/",
        "package_name": "python3.11-minimal_3.11.1-2_amd64.deb",
        "product": "python",
        "version": "3.11.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "python-base_2.7.18-3_x86_64.ipk",
        "product": "python",
        "version": "2.7.18",
    },
    {
        "url": "https://downloads.openwrt.org/releases/22.03.3/packages/x86_64/packages/",
        "package_name": "libpython3-3.10_3.10.9-1_x86_64.ipk",
        "product": "python",
        "version": "3.10.9",
    },
]
