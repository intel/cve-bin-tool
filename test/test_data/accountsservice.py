# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "accountsservice",
        "version": "0.6.45",
        "version_strings": ["accounts-daemon 0.6.45"],
    },
    {
        "product": "accountsservice",
        "version": "0.6.55",
        "version_strings": ["accounts-daemon 0.6.55"],
    },
]
package_test_data = [
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/a/accountsservice/",
        "package_name": "accountsservice_0.6.45-2_amd64.deb",
        "product": "accountsservice",
        "version": "0.6.45",
    },
    {
        "url": "http://mirror.centos.org/centos/8/AppStream/aarch64/os/Packages/",
        "package_name": "accountsservice-0.6.55-1.el8.aarch64.rpm",
        "product": "accountsservice",
        "version": "0.6.55",
    },
]
