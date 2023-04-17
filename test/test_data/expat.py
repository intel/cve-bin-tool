# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libexpat",
        "version": "2.0.1",
        "version_strings": [
            "expat_2.0.1 ",
            "requested feature requires XML_DTD support in Expat",
        ],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "expat-2.1.0-12.el7.x86_64.rpm",
        "product": "libexpat",
        "version": "2.1.0",
    },
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/expat/2.2.1/1.fc24/x86_64/",
        "package_name": "expat-2.2.1-1.fc24.x86_64.rpm",
        "product": "libexpat",
        "version": "2.2.1",
    },
    {
        "url": "http://http.us.debian.org/debian/pool/main/e/expat/",
        "package_name": "libexpat1_2.2.0-2+deb9u3_amd64.deb",
        "product": "libexpat",
        "version": "2.2.0",
    },
]
