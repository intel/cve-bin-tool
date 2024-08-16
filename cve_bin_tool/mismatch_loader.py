import argparse
import itertools
import os
import sqlite3

import yaml

from cve_bin_tool.cvedb import DBNAME, DISK_LOCATION_DEFAULT
from cve_bin_tool.log import LOGGER

SQL_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS mismatch(
    purl TEXT,
    vendor TEXT,
    PRIMARY KEY(purl,vendor)
);
"""

SQL_INSERT_MISMATCH = """
INSERT INTO mismatch (purl, vendor)
VALUES (?, ?)
ON CONFLICT DO NOTHING;
"""

db_path = DISK_LOCATION_DEFAULT / DBNAME
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_dir = os.path.join(parent_dir, "mismatch_data")


def setup_sqlite(data_dir: str, db_file: str) -> bool:
    """
    Walk the given data directory, load the mismatch relationships and write to an SQLite file
    :param data_dir: data directory to walk
    :param db_file: SQLite file to write results into
    :return: Success (True) or Failure (False)
    """
    if os.path.exists(db_file) and not os.access(db_file, os.W_OK):
        LOGGER.error(f"DB file already exists and is not writable: {db_file}")
        return False

    relation_file_name = "mismatch_relations.yml"
    relation_file_paths = []

    for root, directories, files in os.walk(data_dir):
        if relation_file_name in files:
            relation_file_paths.append(os.path.join(root, relation_file_name))

    if not relation_file_paths or len(relation_file_paths) == 0:
        LOGGER.error(f"No relationship files found in: {data_dir}")
        return False

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(SQL_CREATE_TABLE)

    for relation_file_path in relation_file_paths:
        if not os.path.exists(relation_file_path):
            LOGGER.error(f"Vendor file does not exist, skipping: {relation_file_path}")
            continue

        with open(relation_file_path) as relation_file:
            content = yaml.safe_load(relation_file)
            vendor_list = content.get("invalid_vendors", [])
            purls_list = content.get("purls", [])
            purl_vendor_pairs = list(itertools.product(purls_list, vendor_list))
            for purl_vendor_pair in purl_vendor_pairs:
                cursor.execute(SQL_INSERT_MISMATCH, purl_vendor_pair)

    conn.commit()
    conn.close()
    return True


def setup_args():
    """
    Setup command line arguments
    """

    parser = argparse.ArgumentParser(description="mismatch loader")
    parser.add_argument(
        "--dir",
        metavar="DATA_DIR",
        type=str,
        default=data_dir,
        help="Data folder location",
    )
    parser.add_argument(
        "--database",
        "-db",
        type=str,
        default=db_path,
        help="SQLite DB file location",
    )
    args = parser.parse_args()
    return args


def run_mismatch_loader(dir=data_dir, db_file=db_path):
    """
    Runs the mismatch loader to populate the SQLite database with mismatch relationships.

    Args:
        dir (str): The directory containing the data files to be processed.
        db_file (str): The file path to the SQLite database file.

    Returns:
        bool: True if the database setup was successful, False otherwise.
    """
    if not os.path.exists(dir) or not os.path.isdir(dir):
        LOGGER.error(
            f"Specified data directory does not exist or is not a folder: {dir}"
        )
        return False
    return setup_sqlite(dir, db_file)


def main():
    """
    Run the mismatch loader utility
    """
    args = setup_args()

    if not run_mismatch_loader(args.dir, args.database):
        exit(1)
    exit(0)


if __name__ == "__main__":
    main()
