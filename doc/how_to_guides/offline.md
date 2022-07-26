# How do I use CVE Binary Tool in an offline environment?

The cve-bin-tool can be used in offline environments which do not have direct access to the internet to download the latest vulnerability databases.

## Prepare the vulnerability database for offline use
To download the vulnerability database for use in an offline environment, ensure that cve-bin-tool is installed on an internet-connected system.

Run the tool to obtain the latest version of the vulnerability database
```
$ cve-bin-tool --update now
```
NOTE The tool will error with InsufficientArgs because no directory was specified for a scan. This is expected behaviour.

## Export the database

Run the tool to export the latest version of the vulnerability database.
```
$ cve-bin-tool --export <filename>
```

## Transfer the vulnerability database file into a directory in the offline environment

The way of transfer depends on the environment. 

## Import the vulnerability database file on the offline system

Run the tool to import the transferred copy of the vulnerability database.
```
$ cve-bin-tool --import <filename>
```

The cve-bin-tool will fail to operate in offline mode if a vulnerability database is not present on the system.

## Run cve-bin-tool with --offline option
In an offline environment, specify the `--offline` option when running a scan so that cve-bin-tool doesn't attempt to download the latest database files or check for a newer version of the tool.
The `--offline` option is equivalent to specifying `--update never` and `--disable-version-check` options.

## Maintenance Updates
In an offline environment, it is important to update the vulnerability database on a regular basis as often as you feel appropriate, so that the scanner can continue to detect recently-identified vulnerabilities. If any changes to CVE data is required (e.g. to remove false positives), you might also want to create and copy over a triage data file for usage. The time of the latest database update is reported whenever a scan is performed.

It is important to periodically check if the cve-bin-tool has also been updated as this check cannot be performed within an offline environment.
