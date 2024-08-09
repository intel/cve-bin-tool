# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This experiment is an extension of the CI-Pre-Checker github action.(https://github.com/intel/cve-bin-tool/pull/3840)

This script aims to print any and all the checkers which have {product,version} pairs in their VENDOR_PRODUCT which do NOT have any associated,reported CVEs
After this experiment is done and all the pre-existing checkers are taken care of , we can proceed to add the CI-Pre-checker github action for any newly added/updated checkers.

-- Joydeep Tripathy (www.github.com/joydeep049)
"""

import ast
import os
import sqlite3
import sys
from pathlib import Path

OLD_CACHE_DIR = Path("~").expanduser() / ".cache" / "cve-bin-tool" / "cve.db"


def extract_vendor_product(file_path):
    """Extract {vendor,product} pairs from given checker file"""
    vendor_product = None
    with open(file_path) as file:
        inside_vendor_product = False
        vendor_product_str = ""
        for line in file:
            if "VENDOR_PRODUCT" in line:
                inside_vendor_product = True
            if inside_vendor_product:
                vendor_product_str += line.strip()
                if line.strip().endswith("]"):
                    break
        if vendor_product_str:
            vendor_product = ast.literal_eval(vendor_product_str.split("=")[1].strip())
    return vendor_product


def query_database(file_path):
    """Query the database and check whether all the {vendor,product} pairs have associated CVEs"""
    vendor_product = extract_vendor_product(file_path)
    dbcon = sqlite3.connect(OLD_CACHE_DIR)
    cursor = dbcon.cursor()
    for vendor, product in vendor_product:
        cursor.execute(
            "SELECT count(*) FROM cve_range WHERE vendor = ? AND product = ?",
            (vendor, product),
        )
        result = cursor.fetchall()
        # Failing
        if result[0] == 0:
            return False
    # Success
    return True


directory = "/home/joydeep/dev/cve-bin-tool/cve_bin_tool/checkers"
value = None
# Iterate through the files in the directory
for filename in os.listdir(directory):
    # Check if the file is a Python file and not __init__.py
    if filename.endswith(".py") and filename != "__init__.py":
        file_path = os.path.join(directory, filename)
        value = query_database(file_path)
        if value is False:
            print("WARNING::")
            sys.exit(1)
        print(f"For {filename}: {value}")


"""

Result: All the pre-existing checkers are in the clear.
We can go ahead and add the github action.

"""
