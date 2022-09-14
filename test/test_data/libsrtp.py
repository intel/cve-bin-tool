mapping_test_data = [
    {"product": "libsrtp", "version": "1.5.4", "version_strings": ["libsrtp 1.5.4"]},
    {"product": "libsrtp", "version": "2.3.0", "version_strings": ["libsrtp2 2.3.0"]},
]

package_test_data = [
    {
        "url": "https://rpmfind.net/linux/centos/8-stream/AppStream/aarch64/os/Packages/",
        "package_name": "libsrtp-1.5.4-8.el8.aarch64.rpm",
        "product": "libsrtp",
        "version": "1.5.4",
    },
    {
        "url": "https://rpmfind.net/linux/centos-stream/9-stream/AppStream/aarch64/os/Packages/",
        "package_name": "libsrtp-2.3.0-7.el9.aarch64.rpm",
        "product": "libsrtp",
        "version": "2.3.0",
    },
]
