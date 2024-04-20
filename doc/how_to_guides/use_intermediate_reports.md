# How to use intermediate reports

Let's consider a case where multiple groups have done triage separately and want to merge their outputs in a single report. We can do this by saving scans in form of intermediate reports and merge them whenever required.

## Create Intermediate reports
To create an intermediate report on a scan for path `/home/code/backend/`, you can use:

```
python -m cve_bin_tool.cli -a /home/reports/backend.json /home/code/backend/
```
Here we are saving the intermediate report in `/home/reports/backend.json`  
Alternatively, you can just use the directory path omitting the filename. Example:
```
python -m cve_bin_tool.cli -a /home/reports/ -t frontend /home/code/frontend/
```

CVE-Binary Tool will generate a filename with the default naming convention which is: `"append.YYYY-MM-DD.hh-mm-ss.json"`  

Note: You can also use `-t --tag` if you want to add a unique tag inside your intermediate report. By default it is empty and stored as `""`.

Intermediate report format

```json
{
    "metadata": {
        "timestamp": "2021-06-17.00-00-30",
        "tag": "",
        "scanned_dir": "/home/code/backend",
        "products_with_cve": 139,
        "products_without_cve": 2,
        "total_files": 49
    },
    "report": [
        {
            "vendor": "gnu",
            "product": "gcc",
            "version": "9.0.1",
            "cve_number": "CVE-2019-15847",
            "severity": "HIGH",
            "score": "7.5",
            "cvss_version": "3",
            "paths": "/home/code/backend/glib.tar.gz,/home/code/backend/gcc.tar.gz",
            "remarks": "NewFound",
            "comments": ""
        },
        ...
    ]
}
```

## Adding triage information to a merge report

Merged reports can be used to store and/or share triage information about the
vulnerabilities that have been found.

To add triage, you can open up the json file in a text editor or json editor of
your choice to add any changes you need.

The "remarks" section allows 6 values:

1. NewFound
2. Unexplored
3. Confirmed
4. Mitigated
5. False Positive
6. Not Affected

More details such as how a CVE was mitigated or why it can be ignored can be
added into the "comments" section.  Other fields such as severity and score can
also be updated if necessary.


## Merge intermediate reports

You can merge multiple intermediate reports created using `-m --merge` 

```
python -m cve_bin_tool.cli -m /home/reports/
```

`-m --merge` takes a comma-separated string. So, you can also pass filename(s) directly:

```    
python -m cve_bin_tool.cli -m /home/reports/backend.json,/home/reports/append.2021-06-17.00-00-30.json
```

If you want to save the output in some other format (By default, it is console). You can also use `-f --format` and `-o --output-file` while merging intermediate reports.
For example, If you want to generate an HTML report:
```
python -m cve_bin_tool.cli -m /home/reports/ -f html -o /home/reports/merged_intermediate.html
```

    

