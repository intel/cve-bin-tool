# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gnupg",
        "version": "2.2.27",
        "version_strings": ["gpg.conf-2.2.27"],
    },
    {
        "product": "gnupg",
        "version": "2.2.23",
        "version_strings": ["gpg.conf-2.2.23"],
    },
]

package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "gnupg2-2.0.22-5.el7_5.x86_64.rpm",
        "product": "gnupg",
        "version": "2.0.22",
    },
    {
        "url": "http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/",
        "package_name": "gnupg2-2.2.20-2.el8.x86_64.rpm",
        "product": "gnupg",
        "version": "2.2.20",
    },
    {
        "url": "https://download-ib01.fedoraproject.org/pub/fedora/linux/releases/34/Everything/x86_64/os/Packages/g/",
        "package_name": "gnupg1-1.4.23-15.fc34.x86_64.rpm",
        "product": "gnupg",
        "version": "1.4.23",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/9.1/All/",
        "package_name": "gnupg-1.4.23nb11.tgz",
        "product": "gnupg",
        "version": "1.4.23",
    },
]
