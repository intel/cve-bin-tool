import argparse
import os
import sqlite3
from pathlib import Path

from cve_bin_tool.mismatch_loader import run_mismatch_loader

DBNAME = "cve.db"
DISK_LOCATION_DEFAULT = Path("~").expanduser() / ".cache" / "cve-bin-tool"
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_dir = os.path.join(parent_dir, "mismatch_data")
dbpath = DISK_LOCATION_DEFAULT / DBNAME


def lookup(purl, db_file):
    """
    Looks up the vendor information for a given purl in the mismatch database.

    Args:
        purl (str): The package URL to lookup in the mismatch database.
        db_file (str): The file path to the SQLite database file.

    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT vendor FROM mismatch WHERE purl = ?", (purl,))
        result = cursor.fetchall()

        if result:
            formatted_result = ", ".join([row[0] for row in result])
            print(formatted_result)
        else:
            print("Error: No data found for the provided purl.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()


def loader(data_dir, db_file):
    """
    Sets up or refreshes the mismatch database using data from the specified directory.

    Args:
        data_dir (str): The directory containing the data files to be loaded into the mismatch database.
        db_file (str): The file path to the SQLite database file.

    """
    if run_mismatch_loader(data_dir, db_file):
        print("Mismatch database setup completed successfully.")
    else:
        print("Mismatch database setup failed.")


def main():
    parser = argparse.ArgumentParser(description="Mismatch Database Management Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for the lookup command
    lookup_parser = subparsers.add_parser(
        "lookup", help="Look up vendor information for a given purl"
    )
    lookup_parser.add_argument(
        "purl", type=str, help="The package URL to lookup in the mismatch database"
    )
    lookup_parser.add_argument(
        "--database", dest="db_file", default=dbpath, help="SQLite DB file location"
    )

    # Subparser for the loader command
    loader_parser = subparsers.add_parser(
        "loader", help="Set up or refresh the mismatch database"
    )
    loader_parser.add_argument(
        "--dir", dest="data_dir", default=data_dir, help="Data folder location"
    )
    loader_parser.add_argument(
        "--database", dest="db_file", default=dbpath, help="SQLite DB file location"
    )

    args = parser.parse_args()

    if args.command == "lookup":
        lookup(args.purl, args.db_file)
    elif args.command == "loader":
        loader(args.data_dir, args.db_file)
    else:
        loader(data_dir, dbpath)


if __name__ == "__main__":
    main()
