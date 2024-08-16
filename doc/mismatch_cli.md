# Mismatch Database Management Tool Documentation

## Overview

The Mismatch Database Management Tool is a command-line utility designed to facilitate the management and querying of a mismatch database. This tool provides two main functionalities:

1. **Lookup**: Retrieve vendor information for a given Package URL (PURL) from the mismatch database.
2. **Loader**: Set up or refresh the mismatch database using data from a specified directory.

## Prerequisites

Ensure the following Python modules are installed:

- `sqlite3`: For SQLite database operations.
- `argparse`: For command-line argument parsing.
- `cve_bin_tool.mismatch_loader`: To execute the mismatch loader functionality.

## Directory Structure

The script operates within a specific directory structure as shown below:

```
project_root/
│
├── mismatch_data/               # Directory containing the mismatch relations
│
└── mismatch/           # Directory containing the script
    └── cli.py          # The main script file
```

## Data Directory

The `mismatch_data/` directory is a key component of the Mismatch Database Management Tool. It houses the structured data files that are used to populate or refresh the mismatch database.

### Directory Structure

The structure of the `mismatch_data/` directory is organized as follows:

```
mismatch_data/
└── namespace/
    └── product/
        └── mismatch_relations.yml
```

### Explanation of Contents

- **namespace/**: This directory represents a logical grouping, such as a software ecosystem, project, or domain.

- **product/**: Each `namespace/` contains one or more `product/` directories. Each directory corresponds to a specific product within that namespace.

- **mismatch_relations.yml**: This YAML file inside each `product/` directory contains the data related to mismatches. It typically includes:

  - **purls**: A list of package URLs (PURLs) associated with the product. For example:
    ```yaml
    purls:
      - pkg:pypi/zstandard
    ```
  
  - **invalid_vendors**: A list of vendors that are considered invalid or mismatched for the given PURLs. For example:
    ```yaml
    invalid_vendors:
      - facebook
    ```

## Usage

The script can be executed using different subcommands, each serving a distinct purpose.

### 1. Lookup Command

The `lookup` command allows you to search for vendor information based on a PURL in the mismatch database.

**Syntax:**
```bash
python -m mismatch.cli lookup <purl> [--database <db_file>]
```

**Parameters:**
- `<purl>`: (Required) The Package URL to search within the mismatch database.
- `--database`: (Optional) Path to the SQLite database file. Defaults to the pre-configured location if not provided.

**Example:**
```bash
python -m mismatch.cli lookup pkg:namespace/product --database /path/to/mismatch.db
```

### 2. Loader Command

The `loader` command initializes or updates the mismatch database using data from a specified directory.

**Syntax:**
```bash
python -m mismatch.cli loader [--dir <data_dir>] [--database <db_file>]
```

**Parameters:**
- `--dir`: (Optional) Directory containing the data files to be loaded. Defaults to the `mismatch_data/` directory in the project root.
- `--database`: (Optional) Path to the SQLite database file. Defaults to the pre-configured location if not provided.

**Example:**
```bash
python -m mismatch.cli loader --dir /path/to/data --database /path/to/mismatch.db
```

### 3. Default Behavior

If the script is executed without any subcommands, it defaults to running the `loader` command using the default directory and database file:

**Syntax:**
```bash
python -m mismatch.cli
```

This command will trigger the `loader` functionality with default parameters.

## Example Commands

Here are some sample commands that demonstrate how to use the script:

1. **Look Up Vendor Information for a PURL**:
   ```bash
   python -m mismatch.cli lookup pkg:namespace/product
   ```

2. **Refresh the Database Using Default Settings**:
   ```bash
   python -m mismatch.cli
   ```

3. **Specify Custom Data Directory and Database File for Loader**:
   ```bash
   python -m mismatch.cli loader --dir /custom/data/dir --database /custom/db/file.db
   ```

## Conclusion

The Mismatch Database Management Tool is a robust utility designed to streamline the management and querying of a mismatch database.
