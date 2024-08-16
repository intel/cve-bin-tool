# Adding data to mismatch database

CVE Binary Tool uses a number of sources for vulnerability and risk data. Sometimes these can produce name collision, and to tackle this we've created a `mismatch` 
database.

This document details the steps for adding data to the mismatch database.

## 1. Update `mismatch_data/` directory

1. Make a new file with `namespace/product_name/mismatch_relations.yml` name under the `mismatch_data/` directory. For example, `pypi/zstandard/mismatch_relations.yml` for zstandard
from pypi namespace.
2. Populate the file with `purl-invalid_vendor` information.

```yml
  purls:
    - pkg:pypi/zstandard
  invalid_vendors:
    - facebook
```

## 2. Run the populator script

The [`mismatch_loader`](../cve_bin_tool/mismatch_loader.py) script populates the the mismatch database with the contents of `mismatch_data/` directory.

```python
    python -m cve_bin_tool.mismatch_loader
```

The default directory is `mismatch_data/`, and default database file is `cve.db`.

To use a specific directory, use `--dir` flag:
```python
    python -m cve_bin_tool.mismatch_loader --dir directory_location
```

To use a specific database file, use `--database` flag:
```python
    python -m cve_bin_tool.mismatch_loader --database database_file_location
```

## 3. (optional) Make pull request of new-found name collision

If you find invalid relationship, please do following:

- Fork the [repo](https://github.com/intel/cve-bin-tool)
- Update the `mismatch_data/` directory with purl-invalid_vendor information like [this](../data/pypi/zstandard/mismatch_relations.yml)
- Create a pull request with the details of update. [Reference](https://github.com/intel/cve-bin-tool/pull/4239)
