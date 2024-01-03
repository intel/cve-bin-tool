# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "zsh", "version": "5.8", "version_strings": ["zsh/5.8"]},
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/",
        "package_name": "zsh-5.5.1-6.el8_1.2.x86_64.rpm",
        "product": "zsh",
        "version": "5.5.1",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/9.1/All/",
        "package_name": "zsh-5.8nb2.tgz",
        "product": "zsh",
        "version": "5.8",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/z/zsh/",
        "package_name": "zsh_5.8-6+b1_amd64.deb",
        "product": "zsh",
        "version": "5.8",
    },
]
