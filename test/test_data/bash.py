# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {"product": "bash", "version": "1.14.0", "version_strings": ["Bash version 1.14.0"]}
]
package_test_data = [
    {
        "url": "https://kojipkgs.fedoraproject.org/packages/bash/4.0/1.fc11/x86_64/",
        "package_name": "bash-4.0-1.fc11.x86_64.rpm",
        "product": "bash",
        "version": "4.0.0",
    },
    {
        "url": "http://mirrors.cat.pdx.edu/ubuntu/pool/main/b/bash/",
        "package_name": "bash_4.4.18-2ubuntu1_amd64.deb",
        "product": "bash",
        "version": "4.4.19",
    },
]
