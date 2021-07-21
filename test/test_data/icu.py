# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "international_components_for_unicode",
        "version": "60.3",
        "version_strings": ["ICU 60.3"],
    },
    {
        "product": "international_components_for_unicode",
        "version": "60.3",
        "version_strings": ["icu-60.3"],
    },
]
package_test_data = [
    {
        "url": "http://www.rpmfind.net/linux/openmandriva/cooker/repository/x86_64/main/release/",
        "package_name": "icu-68.2-1-omv4002.x86_64.rpm",
        "product": "international_components_for_unicode",
        "version": "68.2",
    },
    {
        "url": "http://mirror.centos.org/centos/8/BaseOS/aarch64/os/Packages/",
        "package_name": "icu-60.3-2.el8_1.aarch64.rpm",
        "product": "international_components_for_unicode",
        "version": "60.3",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/i/icu/",
        "package_name": "icu-devtools_67.1-4_amd64.deb",
        "product": "international_components_for_unicode",
        "version": "67.1",
    },
    {
        "url": "https://ftp.netbsd.org/pub/pkgsrc/packages/NetBSD/amd64/8.2/All/",
        "package_name": "icu-68.2.tgz",
        "product": "international_components_for_unicode",
        "version": "68.2",
    },
    {
        "url": "https://rpmfind.net/linux/dag/redhat/el4/en/x86_64/dag/RPMS/",
        "package_name": "icu-3.6-1.el4.rf.x86_64.rpm",
        "product": "international_components_for_unicode",
        "version": "3.6",
    },
    # {
    #     "url": "https://rpmfind.net/linux/dag/redhat/el4/en/x86_64/dag/RPMS/",
    #     "package_name": "icu-2.6.2-1.2.el4.rf.x86_64.rpm",
    #     "product": "international_components_for_unicode",
    #     "version": "2.6.2",
    # },
]
