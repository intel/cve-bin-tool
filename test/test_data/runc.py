# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "runc", "version": "0.1.1", "version_strings": ["runc-0.1.1"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/aarch64/",
        "package_name": "runc-1.1.4-150000.36.1.aarch64.rpm",
        "product": "runc",
        "version": "1.1.4",
        "other_products": ["go"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/r/runc/",
        "package_name": "runc_0.1.1+dfsg1-2+deb9u1_amd64.deb",
        "product": "runc",
        "version": "0.1.1",
        "other_products": ["go"],
    },
]
