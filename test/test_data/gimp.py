# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gimp",
        "version": "2.6.10",
        "version_strings": ["image-uri\nGIMP 2.6.10"],
    }
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/gimp/2.6.12/1.fc15/x86_64/",
        "package_name": "gimp-2.6.12-1.fc15.x86_64.rpm",
        "product": "gimp",
        "version": "2.6.12",
    },
    {
        "url": "http://ftp.osuosl.org/pub/ubuntu/pool/universe/g/gimp/",
        "package_name": "gimp_2.8.22-1_amd64.deb",
        "product": "gimp",
        "version": "2.8.22",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "gimp-2.8.22-1.el7.x86_64.rpm",
        "product": "gimp",
        "version": "2.8.22",
    },
]
