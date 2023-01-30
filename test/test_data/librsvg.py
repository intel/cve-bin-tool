# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "librsvg",
        "version": "2.46.5",
        "version_strings": ["librsvg-2.46.5"],
    },
    {
        "product": "librsvg",
        "version": "2.50.7",
        "version_strings": ["librsvg2-2.50.7"],
    },
]
package_test_data = [
    {
        "url": "https://ftp.lysator.liu.se/pub/opensuse/distribution/leap/15.3/repo/oss/aarch64/",
        "package_name": "librsvg-2-2-2.46.5-3.3.1.aarch64.rpm",
        "product": "librsvg",
        "version": "2.46.5",
        "other_products": ["rust"],
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/35/Everything/aarch64/os/Packages/l/",
        "package_name": "librsvg2-2.50.7-2.fc35.aarch64.rpm",
        "product": "librsvg",
        "version": "2.50.7",
        "other_products": ["rust"],
    },
]
