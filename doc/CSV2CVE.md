CSV2CVE
=======

This tool takes a comma-delimited file (.csv) with the format `vendor,product,version` and queries the locally stored CVE data (the same data used by the CVE Binary Tool) to give you a list of CVEs that affect each version listed.  

This is meant as a helper tool for folk who know the list of product being used in their software, so that you don't have to rely on binary detection heuristics.  There exist other tools that do this, but it seemed potentially useful to provide both in the same suite of tools, and it also saves users from having to download two copies of the same data.

At the moment, you must use the exact vendor and product strings used in the National Vulnerability Database.  You can read more on how to find the correct string in [the checker documentation](https://github.com/intel/cve-bin-tool/blob/master/cve_bin_tool/checkers/README.md).  Future work could extend this to use the mappings already in the CVE Binary Tool or to use other mappings such as common linux package names for a given distribution.  (Contributions welcome!)


Running the tool:
----------------
`csv2cve <csv_file>`

If you are trying to run a local copy from source, you can also use `python -m cve_bin_tool.csv2cve <csv_file>`

Additional Options:
------------------
```
Output options:
    -l {debug,info,warning,error,critical}, --log {debug,info,warning,error,critical}
                            log level. The default log level is info
Functional options:
    -u {now,daily,never}, --update {now,daily,never}
                            update schedule for NVD database. Default is daily. 
```

Example .csv file:
------------------

Note that this *does* require that the first row be `vendor,product,version` so that the csv parser can do the right thing.  You can have the columns in a different order and/or include other information, but it needs those 3 columns to work.

```python
vendor,product,version
libjpeg-turbo,libjpeg-turbo,2.0.1
haxx,curl,7.59.0
haxx,libcurl,7.59.0
wontwork,no,7.7
```

Example output:
---------------
```console
(venv3.7) [terri@cedar cve-bin-tool]$ python -m cve_bin_tool.csv2cve test/csv/test.csv 
cve_bin_tool.CVEDB - INFO - Using cached CVE data (<24h old). Use -u now to update immediately.
+=================================================================+
|   ___ _    __ ____    ___  ___  _   _    _____  ___  ___  _     |                         
|  / __| \  / /| ___]  |   )[   ]| \ | |  [_   _]| _ || _ || |    |                                   
| | |__ \ \/ / | _]_ = | <   | | | |\| | =  | |  ||_||||_||| |__  |                               
|  \___| \__/  |___ ]  |___)[___]|_| \_|    |_|  |___||___||____| |
|                                                                 |
+=================================================================+
|   CVE Binary Tool Report Generated: 2020-04-30  11:04:24        |
+=================================================================+

+=================================================================+
|   MODULE NAME      |  VERSION  |    CVE NUMBER      | SEVERITY  |
+=================================================================+
| libjpeg-turbo      | 2.0.1     | CVE-2018-19664     | MEDIUM    |
+--------------------+-----------+--------------------+-----------+
| libjpeg-turbo      | 2.0.1     | CVE-2018-20330     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-0500      | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-1000300   | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-1000301   | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-14618     | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-16839     | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-16840     | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-16842     | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2018-16890     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2019-3822      | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2019-3823      | HIGH      |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2019-5436      | HIGH      |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2019-5443      | HIGH      |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2019-5481      | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| curl               | 7.59.0    | CVE-2019-5482      | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| libcurl            | 7.59.0    | CVE-2018-14618     | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| libcurl            | 7.59.0    | CVE-2018-16890     | HIGH      |
+--------------------+-----------+--------------------+-----------+
| libcurl            | 7.59.0    | CVE-2019-3822      | CRITICAL  |
+--------------------+-----------+--------------------+-----------+
| libcurl            | 7.59.0    | CVE-2019-3823      | HIGH      |
+--------------------+-----------+--------------------+-----------+
| libcurl            | 7.59.0    | CVE-2019-5436      | HIGH      |
+--------------------+-----------+--------------------+-----------+
| no                 | 7.7       | UNKNOWN            | UNKNOWN   |
+--------------------+-----------+--------------------+-----------+

