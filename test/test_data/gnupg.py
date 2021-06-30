# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gnupg",
        "version": "2.2.27",
        "version_strings": ["GNU Privacy Guard's OpenPGP server 2.2.27 ready"],
    },
    {
        "product": "gnupg",
        "version": "2.2.23",
        "version_strings": ["GNU Privacy Guard's G13 server 2.2.23 ready"],
    },
]

package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "gnupg2-2.0.22-5.el7_5.x86_64.rpm",
        "product": "gnupg",
        "version": "2.0.22",
    },
]
