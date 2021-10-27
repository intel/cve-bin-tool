# NVD CVE Retrieval API

The CVE API is the next stage in providing up to date vulnerability information for NVD data consumers. The results from this API are updated as quickly as NVD website (unlike the traditional feeds which have explicit update interval of once per day).

This can be also used as a backup if the current JSON feed retrieval interface is removed from the NVD website.

Note: This API retrieval is slower in comparison to the traditional method. 

You can read more about this [here](https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf)

The NVD API is enabled by default or you can explicitly use `-n api` or `--nvd api`:
```
python -m cve_bin_tool.cli -n api
```
A major benefit of using this NVD API is incremental updates.

## What are Incremental Updates?

 With the help of this REST API, we can fetch just the newly added/modified NVD data using the timestamp of your current local database copy.
This will fetch only the CVE entries for which any vulnerability or product string was modified or published later than the above-mentioned timestamp.
This can save users a lot of time and internet bandwidth.

## How to use Incremental Updates?

You can use pre-existing `-u latest` parameter along with the `-n api`. This will simply update your local database and cache copy with the newly published and modified NVD entries.

```
python -m cve_bin_tool.cli -u latest  -n api
```
