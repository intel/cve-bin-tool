# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "rsyslog", "version": "5.5.6", "version_strings": ["rsyslog 5.5.6"]}
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/rsyslog/5.5.7/1.fc15/x86_64/",
        "package_name": "rsyslog-5.5.7-1.fc15.x86_64.rpm",
        "product": "rsyslog",
        "version": "5.5.7",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/main/r/rsyslog/",
        "package_name": "rsyslog_8.2112.0-2ubuntu2_amd64.deb",
        "product": "rsyslog",
        "version": "8.2112.0",
    },
    {
        "url": "http://dl-cdn.alpinelinux.org/alpine/v3.13/main/aarch64/",
        "package_name": "rsyslog-8.2012.0-r3.apk",
        "product": "rsyslog",
        "version": "8.2012.0",
    },
]
