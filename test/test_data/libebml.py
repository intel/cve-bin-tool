# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libebml",
        "version": "1.3.9",
        "version_strings": ["libebml-1.3.9"],
    },
    {
        "product": "libebml",
        "version": "1.3.6",
        "version_strings": ["libebml-1.3.6"],
    },
]

package_test_data = [
    {
        "url": "https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/l/",
        "package_name": "libebml-1.3.9-1.el7.x86_64.rpm",
        "product": "libebml",
        "version": "1.3.9",
    },
    {
        "url": "http://ftp.de.debian.org/debian/pool/main/libe/libebml/",
        "package_name": "libebml4v5_1.3.6-2_amd64.deb",
        "product": "libebml",
        "version": "1.3.6",
    },
]
