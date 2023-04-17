# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "openjpeg", "version": "1.5.1", "version_strings": ["openjpeg-1.5.1"]},
    {"product": "openjpeg", "version": "2.1.0", "version_strings": ["openjpeg2-2.1.0"]},
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/openjpeg/1.5.0/5.fc18/x86_64/",
        "package_name": "openjpeg-1.5.0-5.fc18.x86_64.rpm",
        "product": "openjpeg",
        "version": "1.5.0",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "openjpeg-1.5.1-18.el7.x86_64.rpm",
        "product": "openjpeg",
        "version": "1.5.1",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/o/openjpeg2/",
        "package_name": "libopenjp2-7_2.1.0-2+deb8u3+b1_amd64.deb",
        "product": "openjpeg",
        "version": "2.1.0",
    },
]
