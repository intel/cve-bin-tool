# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "jackson-databind",
        "version": "2.9.10.6",
        "version_strings": ["<tag>jackson-databind-2.9.10.6</tag>"],
    },
    {
        "product": "jackson-databind",
        "version": "2.10.0",
        "version_strings": ["<tag>jackson-databind-2.10.0</tag>"],
    },
    {
        "product": "jackson-databind",
        "version": "2.11.4",
        "version_strings": ["<tag>jackson-databind-2.11.4</tag>"],
    },
]
package_test_data = [
    {
        "url": "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.9.10.6/",
        "package_name": "jackson-databind-2.9.10.6.jar",
        "product": "jackson-databind",
        "version": "2.9.10.6",
    },
    {
        "url": "https://vault.centos.org/centos/8/AppStream/x86_64/os/Packages/",
        "package_name": "jackson-databind-2.10.0-1.module_el8.4.0+782+1d1c31a0.noarch.rpm",
        "product": "jackson-databind",
        "version": "2.10.0",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/releases/35/Everything/x86_64/os/Packages/j/",
        "package_name": "jackson-databind-2.11.4-4.fc35.noarch.rpm",
        "product": "jackson-databind",
        "version": "2.11.4",
    },
]
