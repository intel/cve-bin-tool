# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "syslog-ng",
        "version": "1.5.15",
        "version_strings": ["syslog-ng-1.5.15", "Set syslog-ng control socket"],
    },
    {
        "product": "syslog-ng",
        "version": "3.8.1",
        "version_strings": ["syslog-ng 3.8.1"],
    },
]
package_test_data = [
    {
        "url": "https://mirrors.kernel.org/fedora-buffet/archive/fedora/linux/releases/21/Everything/x86_64/os/Packages/s/",
        "package_name": "syslog-ng-3.5.6-3.fc21.x86_64.rpm",
        "product": "syslog-ng",
        "version": "3.5.6",
    },
    {
        "url": "http://ftp.br.debian.org/debian/pool/main/s/syslog-ng/",
        "package_name": "syslog-ng-core_3.8.1-10_arm64.deb",
        "product": "syslog-ng",
        "version": "3.8.1",
    },
]
