# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from cve_bin_tool.util import ProductInfo, ScanInfo

__all__ = [
    "Parser",
    "java",
    "javascript",
    "python",
    "r",
    "ruby",
    "rust",
    "go",
    "swift",
]


class Parser:
    def __init__(self, cve_db, logger):
        self.cve_db = cve_db
        self.logger = logger
        self.filename = ""

    def run_checker(self, filename):
        pass

    def find_vendor(self, product, version):
        vendor_package_pair = self.cve_db.get_vendor_product_pairs(product)
        vendorlist: list[ScanInfo] = []
        if vendor_package_pair != []:
            # To handle multiple vendors, return all combinations of product/vendor mappings
            for v in vendor_package_pair:
                vendor = v["vendor"]
                file_path = self.filename
                self.logger.debug(f"{file_path} {product} {version} by {vendor}")
                vendorlist.append(
                    ScanInfo(ProductInfo(vendor, product, version), file_path)
                )
            return vendorlist if len(vendorlist) > 0 else None
        return None
