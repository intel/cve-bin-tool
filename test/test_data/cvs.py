# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "cvs",
        "version": "1.12.13",
        "version_strings": ["CVS) 1.12.13"],
    }
]
package_test_data = [
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.4/repo/oss/aarch64/",
        "package_name": "cvs-1.12.13-150400.1.10.aarch64.rpm",
        "product": "cvs",
        "version": "1.12.13",
    },
    {
        "url": "http://rpmfind.net/linux/opensuse/distribution/leap/15.4/repo/oss/ppc64le/",
        "package_name": "cvs-1.12.13-150400.1.10.ppc64le.rpm",
        "product": "cvs",
        "version": "1.12.13",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/cvs/",
        "package_name": "cvs_1.12.13+real-15+deb8u1_amd64.deb",
        "product": "cvs",
        "version": "1.12.13",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/c/cvs/",
        "package_name": "cvs_1.12.13+real-15+deb8u1_armel.deb",
        "product": "cvs",
        "version": "1.12.13",
    },
]
