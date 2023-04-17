# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "openafs", "version": "1.6.12", "version_strings": ["OpenAFS 1.6.12"]}
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/mageia/distrib/5/x86_64/media/core/updates/",
        "package_name": "openafs-client-1.6.13-1.mga5.x86_64.rpm",
        "product": "openafs",
        "version": "1.6.13",
        "other_products": ["gcc"],
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/o/openafs/",
        "package_name": "openafs-client_1.6.15-1ubuntu1_amd64.deb",
        "product": "openafs",
        "version": "1.6.15",
    },
]
