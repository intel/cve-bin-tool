# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "nettle", "version": "3.8.1", "version_strings": ["nettle-3.8.1"]},
    {"product": "nettle", "version": "3.18", "version_strings": ["nettle 3.18"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/aarch64/",
        "package_name": "nettle-3.8.1-150500.1.6.aarch64.rpm",
        "product": "nettle",
        "version": "3.8.1",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/ppc64le/",
        "package_name": "nettle-3.8.1-150500.1.6.ppc64le.rpm",
        "product": "nettle",
        "version": "3.8.1",
    },
]
