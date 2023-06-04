# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "qt",
        "version": "4.2.3",
        "version_strings": ["Qt 4.2.3", r"QTest library 4.2.3"],
    }
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/qt/3.3.8b/8.fc9/i386/",
        "package_name": "qt-3.3.8b-8.fc9.i386.rpm",
        "product": "qt",
        "version": "3.3.8",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "qt-x11-4.8.7-8.el7.x86_64.rpm",
        "product": "qt",
        "version": "4.8.7",
    },
]
