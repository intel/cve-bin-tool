# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "dovecot",
        "version": "2.2.11",
        "version_strings": ["Dovecot v2.2.11", "DOVECOT_VERSION=2.2.11"],
    },
    {
        "product": "dovecot",
        "version": "2.3.21.1",
        "version_strings": ["Dovecot v2.3.21.1", "DOVECOT_VERSION=2.3.21.1"],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/dovecot/2.2.10/1.fc20/x86_64/",
        "package_name": "dovecot-2.2.10-1.fc20.x86_64.rpm",
        "product": "dovecot",
        "version": "2.2.10",
    },
    {
        "url": "http://rpmfind.net/linux/mageia/distrib/5/x86_64/media/core/updates/",
        "package_name": "dovecot-2.2.13-5.1.mga5.x86_64.rpm",
        "product": "dovecot",
        "version": "2.2.13",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/aarch64/9.1/All/",
        "package_name": "dovecot-2.3.15.tgz",
        "product": "dovecot",
        "version": "2.3.15",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/d/dovecot/",
        "package_name": "dovecot-core_2.3.13+dfsg1-1ubuntu1_amd64.deb",
        "product": "dovecot",
        "version": "2.3.13",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/d/dovecot/",
        "package_name": "dovecot-core_2.3.21.1%2Bdfsg1-1_arm64.deb",
        "product": "dovecot",
        "version": "2.3.21.1",
    },
]
