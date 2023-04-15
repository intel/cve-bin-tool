# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "enscript",
        "version": "1.6.6",
        "version_strings": [
            "set the PostScript language level that enscript",
            "or set the environment variable `ENSCRIPT_LIBRARY' to point to your library directory.",
            "GNU Enscript 1.6.6",
        ],
    },
    {
        "product": "enscript",
        "version": "1.6.5",
        "version_strings": [
            "set the PostScript language level that enscript",
            "or set the environment variable `ENSCRIPT_LIBRARY' to point to your library directory.",
            "GNU Enscript 1.6.5",
        ],
    },
]
package_test_data = [
    {
        "url": "http://mirror.centos.org/altarch/7/os/aarch64/Packages/",
        "package_name": "enscript-1.6.6-7.el7.aarch64.rpm",
        "product": "enscript",
        "version": "1.6.6",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/e/enscript/",
        "package_name": "enscript_1.6.5.90-3_amd64.deb",
        "product": "enscript",
        "version": "1.6.5",
    },
]
