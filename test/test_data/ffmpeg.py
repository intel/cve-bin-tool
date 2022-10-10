# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "ffmpeg",
        "version": "4.1.3",
        "version_strings": [
            "%s version 4.1.3",
            "Codec '%s' is not recognized by FFmpeg.",
        ],
    },
    {
        "product": "ffmpeg",
        "version": "3.4.9",
        "version_strings": ["FFmpeg version 3.4.9"],
    },
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/f/ffmpeg/",
        "package_name": "ffmpeg_4.3.1-4ubuntu1_amd64.deb",
        "product": "ffmpeg",
        "version": "4.3.1",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/packages/",
        "package_name": "libffmpeg-full_3.4.9-1_x86_64.ipk",
        "product": "ffmpeg",
        "version": "3.4.9",
    },
]
