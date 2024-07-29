# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "kubernetes",
        "version": "1.20.5",
        "version_strings": [r"kubernetes-1.20.5"],
    },
]
package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/opensuse/distribution/leap/15.2/repo/oss/x86_64/",
        "package_name": "kubernetes-client-1.18.0-lp152.1.4.x86_64.rpm",
        "product": "kubernetes",
        "version": "1.18.0",
        "other_products": ["go"],
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/k/kubernetes/",
        "package_name": "kubernetes-client_1.20.5+really1.20.2-1_amd64.deb",
        "product": "kubernetes",
        "version": "1.20.5",
        "other_products": ["go"],
    },
]
