# pylint: disable=invalid-name
"""
CVE checker for systemd

https://www.cvedetails.com/product/38088/Freedesktop-Systemd.html?vendor_id=7971
"""
from . import Checker


class SystemdChecker(Checker):
    CONTAINS_PATTERNS = [
        r"sd_bus_error_copy",
        r"sd_bus_error_is_set",
        r"sd_bus_error_add_map",
    ]
    FILENAME_PATTERNS = [r"libsystemd.so."]
    VERSION_PATTERNS = [
        r"LIBSYSTEMD_([0-4]+[0-9]+[0-9]+)",
        r"^systemd (\d{2,4})$",
        r"libsystemd-shared-([0-9]+)\.so",
        r"systemd-[a-z]+-([0-9]+)\.so",
        r"udev-([0-9]+)\.so",
        r"systemd v([0-9]+).* running in ",
        r"pam_systemd.so-([0-9]+)\.",
    ]
    VENDOR_PRODUCT = [("freedesktop", "systemd")]
