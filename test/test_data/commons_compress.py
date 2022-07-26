# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "commons_compress",
        "version": "1.18",
        "version_strings": [
            "<artifactId>commons-compress</artifactId>\r\n  <version>1.18</version>"
        ],
    },
    {
        "product": "commons_compress",
        "version": "1.15.1",
        "version_strings": [
            "<artifactId>commons-compress</artifactId>\r\n  <version>1.15.1</version>"
        ],
    },
]
package_test_data = [
    {
        "url": "https://repo1.maven.org/maven2/org/apache/commons/commons-compress/1.16.1/",
        "package_name": "commons-compress-1.16.1.jar",
        "product": "commons_compress",
        "version": "1.16.1",
    },
    {
        "url": "http://rpmfind.net/linux/fedora/linux/releases/35/Everything/x86_64/os/Packages/a/",
        "package_name": "apache-commons-compress-1.21-1.fc35.noarch.rpm",
        "product": "commons_compress",
        "version": "1.21",
    },
]
