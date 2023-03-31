# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "netkit_ftp",
        "version": "0.17",
        "version_strings": ["$NetKit: netkit-ftp-0.17 $"],
    }
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/n/netkit-ftp/",
        "package_name": "ftp_0.17-34.1.1_amd64.deb",
        "product": "netkit_ftp",
        "version": "0.17",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/n/netkit-ftp/",
        "package_name": "ftp_0.17-31_amd64.deb",
        "product": "netkit_ftp",
        "version": "0.17",
    },
]
