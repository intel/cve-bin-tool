# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "lighttpd",
        "version": "1.4.30",
        "version_strings": ["Invalid fds at startup with lighttpd", "lighttpd/1.4.30"],
    }
]
package_test_data = [
    {
        "url": "http://mirrors.kernel.org/fedora/releases/33/Everything/x86_64/os/Packages/l/",
        "package_name": "lighttpd-1.4.55-4.fc33.x86_64.rpm",
        "product": "lighttpd",
        "version": "1.4.55",
    },
    {
        "url": "https://ftp.lysator.liu.se/pub/opensuse/distribution/leap/15.1/repo/oss/x86_64/",
        "package_name": "lighttpd-1.4.49-lp151.2.3.x86_64.rpm",
        "product": "lighttpd",
        "version": "1.4.49",
    },
]
