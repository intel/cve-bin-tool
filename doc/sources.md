# Adding a new data source to cve-bin-tool

CVE Binary Tool users a number of sources for vulnerability and risk data.  You can find more details about them in [the data sources section of the cve-bin-tool manual](MANUAL.html#data-sources).

This document details the steps for adding a new data source.  At the time of this writing, [the purl2cpe pull request](https://github.com/intel/cve-bin-tool/pull/4179/files) shows you the most recent new data source to be added, so you may find that useful to read as an example.

## 1. Create the data source class

1. Make a new file with an appropriate name the `cve_bin_tool/data_sources` directory
2. Make a `Data_Source` for your new source inside that file.   You can look at the other data sources for how the `__init__` function parameters are set up, but don't bother duplicating much of the rest of it.
   - The function that matters is the `get_cve_data` one.  That's the one that's called in cvedb when the data sources are updated.
   - The function name becomes slightly nonsensical here if you're not actually getting CVE data but we haven't refactored it to something like `get_data()` yet.
3. Inside the `get_cve_data()` function, you want to download the your data and stick it in the `.cache` directory.  You should be able to figure that out by looking at the other data sources; make sure to include error checking for failures during the request call so it'll fail gracefully if there's a timeout or something.
4. You will also need to set `self.source_name` in `__init__`.


## 2. Add the new data source to cli.py as a source

There are two places in `cli.py` where you need to make changes.  One is to add the source as an import, the other is to allow it to be disabled on the command line.

Import the data source near the top of the file where it says:

```python
    from cve_bin_tool.data_sources import (
```

Add the ability to enable/disable the source near where the code says

```python
    # Maintain list of sources that are used
    enabled_sources = []
```

There's lots of examples there to follow.  If you were adding a source called "MySource" it would look like this:

```python
    if "MYSOURCE" not in disabled_sources:
        source_mysource = mysource_source.MySource_Source()
        enabled_sources.append(source_mysource)
```

# 3. (optional) Make changes to cvedb.py for loading data

If any special instructions are needed to add the data to existing tables, this can be done in the `populatedb()` function within cvedb.py.  This may not be necessary if you are storing data in a separate table or database and do not need to adjust existing information.

# 4. Add tests

Add any tests needed to make sure your code works.  Be careful about any tests that require huge data loads: you should be using mock data in tests whenever possible.

There is already a test that looks for disabled messages so you don't need to add that one.

# 5. Add documentation

Add documentation for your new source.  Usually this goes in MANUAL.md with a brief mention in README.md
