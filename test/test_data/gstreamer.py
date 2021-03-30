# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "gstreamer",
        "version": "1.10.0",
        "version_strings": [
            "http://bugzilla.gnome.org/enter_bug.cgi?product=GStreamer",
            "libgstreamer-1.10.0",
        ],
    }
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/g/gstreamermm-1.0/",
        "package_name": "libgstreamermm-1.0-0v5_1.4.3+dfsg-5_amd64.deb",
        "product": "gstreamer",
        "version": "1.0",
    },
    {
        "url": "http://mirror.centos.org/centos/7/os/x86_64/Packages/",
        "package_name": "gstreamer-0.10.36-7.el7.i686.rpm",
        "product": "gstreamer",
        "version": "0.10",
    },
]
