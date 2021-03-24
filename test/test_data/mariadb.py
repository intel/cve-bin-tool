# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "mariadb",
        "version": "10.3.22",
        "version_strings": [
            r"10.3.22-MariaDB",
            r"Oracle, MariaDB Corporation Ab and others.",
            r"General information about MariaDB can be found at\nhttp://mariadb.org",
            r"Welcome to the MariaDB monitor.",
            r"MariaDB virtual IO plugin for socket communication",
        ],
    }
]
package_test_data = [
    {
        "url": "http://ports.ubuntu.com/pool/universe/m/mariadb-10.3/",
        "package_name": "mariadb-client-core-10.3_10.3.22-1ubuntu1_arm64.deb",
        "product": "mariadb",
        "version": "10.3.22",
    }
]
