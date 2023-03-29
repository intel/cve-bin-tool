# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gstreamer",
        "version": "0.10.36",
        "version_strings": ["gstreamer\nLGPL\n0.10.36"],
    },
    {
        "product": "gstreamer",
        "version": "1.16.2",
        "version_strings": ["1.16.2\nGStreamer core"],
    },
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "gstreamer-0.10.36-7.el7.i686.rpm",
        "product": "gstreamer",
        "version": "0.10.36",
    },
    {
        "url": "http://ftp.fr.debian.org/debian/pool/main/g/gstreamer1.0/",
        "package_name": "libgstreamer1.0-0_1.10.4-1_amd64.deb",
        "product": "gstreamer",
        "version": "1.10.4",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libgstreamer1_1.16.2-2_x86_64.ipk",
        "product": "gstreamer",
        "version": "1.16.2",
    },
]
