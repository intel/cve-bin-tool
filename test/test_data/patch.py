# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "patch", "version": "2.7.5", "version_strings": ["2.7.5\nGNU patch"]},
    {"product": "patch", "version": "2.7.5", "version_strings": ["GNU patch\n2.7.5"]},
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/aarch64/",
        "package_name": "patch-2.7.6-150000.5.3.1.aarch64.rpm",
        "product": "patch",
        "version": "2.7.6",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.5/repo/oss/ppc64le/",
        "package_name": "patch-2.7.6-150000.5.3.1.ppc64le.rpm",
        "product": "patch",
        "version": "2.7.6",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/patch/",
        "package_name": "patch_2.7.5-1+deb8u1_amd64.deb",
        "product": "patch",
        "version": "2.7.5",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/p/patch/",
        "package_name": "patch_2.7.5-1+deb8u1_armel.deb",
        "product": "patch",
        "version": "2.7.5",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "patch_2.7.6-6_x86_64.ipk",
        "product": "patch",
        "version": "2.7.6",
    },
]
