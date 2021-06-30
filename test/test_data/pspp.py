# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "pspp",
        "version": "1.2.0",
        "version_strings": ["libpspp-1.2.0"],
    },
    {
        "product": "pspp",
        "version": "1.4.0",
        "version_strings": ["libpspp-1.4.0"],
    },
]
package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/opensuse/distribution/leap/15.1/repo/oss/x86_64/",
        "package_name": "pspp-1.2.0-lp151.2.1.x86_64.rpm",
        "product": "pspp",
        "version": "1.2.0",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/33/Everything/aarch64/os/Packages/p/",
        "package_name": "pspp-1.4.0-1.fc33.aarch64.rpm",
        "product": "pspp",
        "version": "1.4.0",
    },
]
