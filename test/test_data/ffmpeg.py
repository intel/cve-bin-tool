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
    }
]
package_test_data = [
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/f/ffmpeg/",
        "package_name": "ffmpeg_4.3.1-4ubuntu1_amd64.deb",
        "product": "ffmpeg",
        "version": "4.3.1",
    }
]
