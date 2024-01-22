# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
A lazy script for searching the database via regexes.

This particular version was used to support the conclusion that my hash detection attempt
in a version_compare PR would do more harm than good, but I'm checking it in so people can modify
it for other data searches in future.

- Terri Oda
"""

import re
import sqlite3

dbcon = sqlite3.connect("/home/terri/.cache/cve-bin-tool/cve.db")
dbcon.create_function("regexp", 2, lambda x, y: 1 if re.search(x, y) else 0)
cursor = dbcon.cursor()

print("StartIncluding ===========")
cursor.execute(
    "select vendor, product, versionStartIncluding from cve_range where versionStartIncluding REGEXP '[0-9a-fA-F]{8}'"
)
results = cursor.fetchall()
for i in results:
    print(i)

print("StartExcluding ===========")
cursor.execute(
    "select vendor, product, versionStartExcluding from cve_range where versionStartExcluding REGEXP '[0-9a-fA-F]{8}'"
)
results = cursor.fetchall()
for i in results:
    print(i)

print("EndExcluding ===========")
cursor.execute(
    "select vendor, product, versionEndExcluding from cve_range where versionEndExcluding REGEXP '[0-9a-fA-F]{8}'"
)
results = cursor.fetchall()
for i in results:
    print(i)

print("EndIncluding ===========")
cursor.execute(
    "select vendor, product, versionEndIncluding from cve_range where versionEndIncluding REGEXP '[0-9a-fA-F]{8}'"
)
results = cursor.fetchall()
for i in results:
    print(i)
