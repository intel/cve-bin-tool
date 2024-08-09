---
name: 'Report a false positive or incorrect component (mismatch)'
about: Template for reporting false positive
title: 'bug: incorrect detection for [product name]'
labels: bug
assignees: ''

---

### Description

Add a short description of the invalid vendor-product relation.

```yml
  purls:
    - [purl identifier] (e.g. pkg:pypi/zstandard.  This will be in the format pkg:[package repository]/[product name])

  invalid_vendors:
    - [list of vendors that shouldn't be detected] (e.g. facebook)
```

Not sure how to fill this out? Give us the CVE number that's being incorrectly detected and we'll try to figure it out from there.

### Instructions

[How to add a new entry to the mismatch database](https://github.com/intel/cve-bin-tool/blob/main/doc/mismatch_data.md)

