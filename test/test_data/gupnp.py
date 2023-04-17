# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gupnp",
        "version": "1.2.7",
        "version_strings": [
            "GUPnPContext: Unable to listen on ",
            "%s GUPnP/1.2.7 DLNADOC/",
        ],
    },
    {
        "product": "gupnp",
        "version": "1.0.6",
        "version_strings": [
            "GUPnPContext: Unable to listen on ",
            "%s GUPnP/1.0.6 DLNADOC/",
        ],
    },
]
package_test_data = [
    {
        "url": "https://eu.mirror.archlinuxarm.org/aarch64/extra/",
        "package_name": "gupnp-1.2.7-1-aarch64.pkg.tar.xz",
        "product": "gupnp",
        "version": "1.2.7",
        "other_products": ["gcc"],
    },
    {
        "url": "http://mirror.centos.org/centos/8/AppStream/aarch64/os/Packages/",
        "package_name": "gupnp-1.0.6-2.el8_4.aarch64.rpm",
        "product": "gupnp",
        "version": "1.0.6",
    },
]
