CSV2CVE
=======

This tool takes a comma-delimited file (.csv) with the format `vendor,package,version` and queries the locally stored CVE data (the same data used by the CVE Binary Tool) to give you a list of CVEs that affect each version listed.  

This is meant as a helper tool for folk who know the list of packages being used in their software, so that you don't have to rely on binary detection heuristics.  There exist other tools that do this, but it seemed potentially useful to provide both in the same suite of tools, and it also saves users from having to download two copies of the same data.

At the moment, you must use the exact vendor and package strings used in the National Vulnerability Database.  You can read more on how to find the correct string in [the checker documentation](https://github.com/intel/cve-bin-tool/blob/master/cve_bin_tool/checkers/README.md).  Future work could extend this to use the mappings already in the CVE Binary Tool or to use other mappings such as common linux package names for a given distribution.  (Contributions welcome!)


Running the tool:
----------------
`csv2cve <csv_file>`

If you are trying to run a local copy from source, you can also use `python -m cve_bin_tool.csv2cve <csv_file>`

Example .csv file:
------------------

Note that this *does* require that the first row be `vendor,package,version` so that the csv parser can do the right thing.  You can have the columns in a different order and/or include other information, but it needs those 3 columns to work.

```python
vendor,package,version
libjpeg-turbo,libjpeg-turbo,2.0.1
haxx,curl,7.59.0
haxx,libcurl,7.59.0
wontwork,no,7.7
```

Example output:
---------------
```console
(venv3.6) terri@sandia:~/Code/cve-bin-tool$ python -m cve_bin_tool.csv2cve test.csv 
opening file: test.csv
Last Update: 2019-07-02
Local database has been updated in the past 24h.
New data not downloaded.  Remove old files present at /home/terri/.cache/cve-bin-tool to force the update.
CVES for libjpeg-turbo libjpeg-turbo, version 2.0.1
CVE-2018-19664
CVE-2018-20330

CVES for haxx curl, version 7.59.0
CVE-2018-0500
CVE-2018-1000300
CVE-2018-1000301
CVE-2018-14618
CVE-2018-16839
CVE-2018-16840
CVE-2018-16842
CVE-2018-16890
CVE-2019-3822
CVE-2019-3823
CVE-2019-5436

CVES for haxx libcurl, version 7.59.0
CVE-2018-14618
CVE-2018-16890
CVE-2019-3822
CVE-2019-3823
CVE-2019-5436

CVES for wontwork no, version 7.7
No CVEs found. Is the vendor/package info correct?

```
