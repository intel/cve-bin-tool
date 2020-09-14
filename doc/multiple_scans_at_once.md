# Best practices for running multiple scans at once

If you're running multiple instances of cve-bin-tool at once, you could
potentially cause a race condition where multiple processes are trying
to update the database from nvd at the same time.  This is not ideal.

To avoid this, you should use a single command to run the nvd update, then turn off the updater in all other copies.  

## Step 1: Update
To update (without scanning) you can use the following command:

```
cve-bin-tool -u now
```

We recommend once per day, but this can be more frequently or less frequently depending on your needs.  Ideally, you want to be sure this completes before you kick off any other scans, so that you aren't checking against a partial database.

## Step 2: Scan

Each parallel instance of cve-bin-tool can then be invoked as follows:

```
cve-bin-tool -u never $path_to_directory_or_file
```






