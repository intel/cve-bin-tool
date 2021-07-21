# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "liblas",
        "version": "1.8.1",
        "version_strings": ["libLAS 1.8.1"],
    }
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/libl/liblas/",
        "package_name": "liblas3_1.8.1-6build1_amd64.deb",
        "product": "liblas",
        "version": "1.8.1",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/x86_64/os/Packages/l/",
        "package_name": "liblas-1.8.1-15.gitd76a061.fc35.i686.rpm",
        "product": "liblas",
        "version": "1.8.1",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/l/",
        "package_name": "liblas-1.8.0-3.el7.x86_64.rpm",
        "product": "liblas",
        "version": "1.8.0",
    },
]
