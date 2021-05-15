# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import csv
import re
import subprocess
from importlib.metadata import version
from os.path import dirname, join

ROOT_PATH = join(dirname(__file__), "..")

REQ_TXT = join(ROOT_PATH, "requirements.txt")
REQ_CSV = join(ROOT_PATH, "requirements.csv")
DOC_TXT = join(ROOT_PATH, "doc", "requirements.txt")
DOC_CSV = join(ROOT_PATH, "doc", "requirements.csv")

SCAN_CSV = join(ROOT_PATH, "cve_bin_tool_requirements.csv")

HTML_DEP_PATH = join(
    ROOT_PATH,
    "cve_bin_tool",
    "output_engine",
    "html_reports",
    "js",
)

HTML_DEP_CSV = join(HTML_DEP_PATH, "dependencies.csv")

# Dependencies that currently have CVEs
# Remove from the list once they are updated
ALLOWED_PACKAGES = ["reportlab"]


def get_out_of_sync_packages(csv_name, txt_name):

    new_packages = set()
    removed_packages = set()
    csv_package_names = set()
    txt_package_names = set()

    with open(csv_name) as csv_file, open(txt_name) as txt_file:
        csv_reader = csv.reader(csv_file)
        next(csv_reader)
        for (_, product) in csv_reader:
            csv_package_names.add(product)
        lines = txt_file.readlines()
        for line in lines:
            txt_package_names.add(re.split(">|\\[|;|=|\n", line)[0])
        new_packages = txt_package_names - csv_package_names
        removed_packages = csv_package_names - txt_package_names

    return (new_packages, removed_packages)


# Test to check if the requirements.csv files are in sync with requirements.txt files
def test_txt_csv_sync():

    errors = set()

    (
        req_new_packages,
        req_removed_packages,
    ) = get_out_of_sync_packages(REQ_CSV, REQ_TXT)
    (
        doc_new_packages,
        doc_removed_packages,
    ) = get_out_of_sync_packages(DOC_CSV, DOC_TXT)

    if doc_removed_packages != set():
        errors.add(
            f"The requirements.txt and requirements.csv files of docs are out of sync! Please remove {', '.join(doc_removed_packages)} from the respective requirements.csv file\n"
        )
    if doc_new_packages != set():
        errors.add(
            f"The requirements.txt and requirements.csv files of docs are out of sync! Please add {', '.join(doc_new_packages)} to the respective requirements.csv file\n"
        )
    if req_removed_packages != set():
        errors.add(
            f"The requirements.txt and requirements.csv files of cve-bin-tool are out of sync! Please remove {', '.join(req_removed_packages)} from the respective requirements.csv file\n"
        )
    if req_new_packages != set():
        errors.add(
            f"The requirements.txt and requirements.csv files of cve-bin-tool are out of sync! Please add {', '.join(req_new_packages)} to the respective requirements.csv file\n"
        )

    assert errors == set(), f"The error(s) are:\n {''.join(errors)}"


def get_cache_csv_data(file):

    data = []

    with open(file) as f:
        r = csv.reader(f)
        next(r)
        for (vendor, product) in r:
            if file is HTML_DEP_CSV:
                file_name = f"{HTML_DEP_PATH}/{product}"
                if not file_name.endswith(".js"):
                    file_name += ".js"
                with open(file_name) as f:
                    file_content = f.read()
                    html_dep_version = re.search(
                        r"v([0-9]+\.[0-9]+\.[0-9]+)", file_content
                    ).group(1)
                    if product not in ALLOWED_PACKAGES:
                        data.append((vendor, product, html_dep_version))
            else:
                if "_not_in_db" not in vendor and product not in ALLOWED_PACKAGES:
                    data.append((vendor, product, version(product)))

        return data


# Test to check for CVEs in cve-bin-tool requirements/dependencies
def test_requirements():

    cache_csv_data = (
        get_cache_csv_data(REQ_CSV)
        + get_cache_csv_data(DOC_CSV)
        + get_cache_csv_data(HTML_DEP_CSV)
    )

    # writes a cache CSV file
    with open(SCAN_CSV, "w") as f:
        writer = csv.writer(f)
        fieldnames = ["vendor", "product", "version"]
        writer = csv.writer(f)
        writer.writerow(fieldnames)
        for row in cache_csv_data:
            writer.writerow(row)

    cve_check = subprocess.run(
        ["python", "-m", "cve_bin_tool.cli", "--input-file", SCAN_CSV]
    )
    assert (
        cve_check.returncode == 0
    ), f"{cve_check.returncode} dependencies/requirements have CVEs"
