# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "berkeley_db",
        "version": "11.2.5.1.29",
        "version_strings": [
            "BDB1568 Berkeley DB library does not support DB_REGISTER on this system",
            "Berkeley DB 11g Release 2, library version 11.2.5.1.29: (date goes here)",
        ],
    }
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "libdb-5.3.21-25.el7.i686.rpm",
        "product": "berkeley_db",
        "version": "11.2.5.3.21",
    }
]
