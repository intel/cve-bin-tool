# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gpgme",
        "version": "1.16.0",
        "version_strings": [
            "GPGME-Tool 1.16.0 ready",
            "This is GPGME 1.16.0 - The GnuPG Made Easy library",
        ],
    },
    {
        "product": "gpgme",
        "version": "1.13.1",
        "version_strings": [
            "GPGME-Tool 1.13.1 ready",
            "This is GPGME 1.13.1 - The GnuPG Made Easy library",
        ],
    },
]
package_test_data = [
    {
        "url": "https://eu.mirror.archlinuxarm.org/aarch64/core/",
        "package_name": "gpgme-1.16.0-1-aarch64.pkg.tar.xz",
        "product": "gpgme",
        "version": "1.16.0",
        "other_products": ["gcc"],
    },
    {
        "url": "https://ftp.lysator.liu.se/pub/opensuse/ports/aarch64/distribution/leap/15.2/repo/oss/aarch64/",
        "package_name": "gpgme-1.13.1-lp152.2.1.aarch64.rpm",
        "product": "gpgme",
        "version": "1.13.1",
    },
]
