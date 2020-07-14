#!/usr/bin/python3

"""
CVE checker for memcached

https://www.cvedetails.com/product/26610/Memcached-Memcached.html?vendor_id=12993

"""
from . import Checker


class MemcachedChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = [r"memcached"]
    VERSION_PATTERNS = [r"memcached ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("memcached", "memcached")]
