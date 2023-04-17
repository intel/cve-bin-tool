# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "libxslt",
        "version": "1.1.28",
        "version_strings": ["libxslt.so.1.1.28", "xsltproc.debug"],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/altarch/7/os/aarch64/Packages/",
        "package_name": "libxslt-1.1.28-6.el7.aarch64.rpm",
        "product": "libxslt",
        "version": "1.1.28",
    },
    {
        "url": "http://xmlsoft.org/sources/",
        "package_name": "libxslt-1.1.33-0rc1.fc26.x86_64.rpm",
        "product": "libxslt",
        "version": "1.1.33",
    },
]
