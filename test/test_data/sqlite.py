# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "sqlite",
        "version": "3.30.1",
        "version_strings": [
            "2019-10-10 20:19:45 18db032d058f1436ce3dea84081f4ee5a0f2259ad97301d43c426bc7f3df1b0b\nSQLITE",
            "ESCAPE expression must be a single character",
        ],
    },
    {
        "product": "sqlite",
        "version": "3.16.1",
        "version_strings": [
            "2017-01-03 18:27:03 979f04392853b8053817a3eea2fc679947b437fd\nSQLITE",
            "ESCAPE expression must be a single character",
        ],
    },
    {
        "product": "sqlite",
        "version": "3.12.2",
        "version_strings": [
            "2016-04-18 17:30:31 92dc59fd5ad66f646666042eb04195e3a61a9e8e\nSQLITE",
            "ESCAPE expression must be a single character",
        ],
    },
    {
        "product": "sqlite",
        "version": "3.12.2",
        "version_strings": [
            "2016-04-18 17:30:31 92dc59fd5ad66f646666042eb04195e3a61aalt2\nSQLITE",
            "ESCAPE expression must be a single character",
        ],
    },
    {
        "product": "sqlite",
        "version": "2020.04.06 18:16:31 1e4b6a93987cdfbf829e2ff35ef417c290625f2894ad11949e301af518f1fb44",
        "version_strings": [
            "2020-04-06 18:16:31 1e4b6a93987cdfbf829e2ff35ef417c290625f2894ad11949e301af518f1fb44\nSQLite",
        ],
    },
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/sqlite/3.16.2/1.fc26/x86_64/",
        "package_name": "sqlite-3.16.2-1.fc26.x86_64.rpm",
        "product": "sqlite",
        "version": "3.16.2",
    },
    {
        "url": "http://rpmfind.net/linux/atrpms/el4-x86_64/atrpms/stable/",
        "package_name": "sqlite-3.1.2-2.99_2.el4.at.i386.rpm",
        "product": "sqlite",
        "version": "3.1.2",
    },
]
