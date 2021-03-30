# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "bzip2", "version": "1.0.2", "version_strings": ["bzip2-1.0.2"]}
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/bzip2/1.0.4/10.fc7/x86_64/",
        "package_name": "bzip2-1.0.4-10.fc7.x86_64.rpm",
        "product": "bzip2",
        "version": "1.0.4",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "bzip2-1.0.6-13.el7.x86_64.rpm",
        "product": "bzip2",
        "version": "1.0.6",
    },
]
