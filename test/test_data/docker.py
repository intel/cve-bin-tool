mapping_test_data = [
    {
        "product": "docker",
        "version": "19.03.15",
        "version_strings": ["docker-ce-19.03.15", "moby-24.0.7"],
    },
]

package_test_data = [
    {
        "url": "https://www.rpmfind.net/linux/mageia/distrib/8/armv7hl/media/core/release/",
        "product": "docker",
        "version": "19.03.15",
        "package_name": "docker-19.03.15-1.mga8.armv7hl.rpm",
        "other_products": [
            "go",
        ],
    },
    {
        "url": "https://www.rpmfind.net/linux/openmandriva/cooker/repository/aarch64/main/release/",
        "product": "docker",
        "version": "24.0.7",
        "package_name": "docker-24.0.7-2-omv2390.aarch64.rpm",
        "other_products": [
            "gcc",
            "go",
            "moby",
        ],
    },
]
