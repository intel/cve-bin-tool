# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "busybox", "version": "1.18.3", "version_strings": ["BusyBox v1.18.3"]}
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/busybox/1.28.2/1.fc29/x86_64/",
        "package_name": "busybox-1.28.2-1.fc29.x86_64.rpm",
        "product": "busybox",
        "version": "1.28.2",
    },
    {
        "url": "http://archive.ubuntu.com/ubuntu/pool/universe/b/busybox/",
        "package_name": "busybox_1.18.5-1ubuntu4_amd64.deb",
        "product": "busybox",
        "version": "1.18.5",
    },
]
