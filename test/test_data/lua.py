# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

mapping_test_data = [
    {
        "product": "lua",
        "version": "5.1.5",
        "version_strings": [
            "Lua 5.1.5  Copyright (C) 1994-2012 Lua.org, PUC-Rio",
            "PANIC: unprotected error in call to Lua API (%s)",
            '-o name  output to file `name\' (default is "luac.out")',
        ],
    },
    {
        "product": "lua",
        "version": "5.0.3",
        "version_strings": [
            "Lua 5.0.3  Copyright (C) 1994-2006 Tecgraf, PUC-Rio",
            "PANIC: unprotected error in call to Lua API (%s)",
            '-o name  output to file `name\' (default is "luac.out")',
        ],
    },
]
package_test_data = [
    {
        "url": "https://ftp.lysator.liu.se/pub/opensuse/tumbleweed/repo/oss/x86_64/",
        "package_name": "lua51-5.1.5-15.11.x86_64.rpm",
        "product": "lua",
        "version": "5.1.5",
    },
    {
        "url": "http://ports.ubuntu.com/pool/universe/l/lua50/",
        "package_name": "lua50_5.0.3-8_arm64.deb",
        "product": "lua",
        "version": "5.0.3",
    },
    {
        "url": "https://downloads.openwrt.org/releases/packages-19.07/x86_64/base/",
        "package_name": "liblua5.1.5_5.1.5-3_x86_64.ipk",
        "product": "lua",
        "version": "5.1.5",
    },
]
