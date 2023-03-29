# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "memcached", "version": "1.4.1", "version_strings": ["memcached 1.4.1"]}
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/memcached/1.4.0/1.fc12/x86_64/",
        "package_name": "memcached-1.4.0-1.fc12.x86_64.rpm",
        "product": "memcached",
        "version": "1.4.0",
    },
    {
        "url": "https://mirrors.edge.kernel.org/centos/7/os/x86_64/Packages/",
        "package_name": "memcached-1.4.15-10.el7_3.1.x86_64.rpm",
        "product": "memcached",
        "version": "1.4.15",
    },
]
