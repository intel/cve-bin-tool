---
name: 'Docstring request'
about: Issue for adding docstrings to a file
title: 'docs: Add docstrings to FILENAME'
labels: ["documentation", "good first issue", "gsoc"]
assignees: ''

---


We haven't been entirely consistent about adding python docstrings to every
function, and I'd like to start improving the codebase. I'm filing separate
tickets for each file I want updated so GSoC folk can claim them more easily --
**please do not claim more than one of these issues; they are intended for
beginners to get their first commit.**

### What is a docstring?

Here's a [tutorial on
docstrings](https://www.programiz.com/python-programming/docstrings) in case
you're not sure what they are.  Basically I want someone to write a short
sentence explaining what a function does and have it put at the top of the
function in the way that python expects docstrings to look.  (You can also do
classes and methods.)  Among other things, docstrings can be used by integrated
development environments (IDEs) to give contributors a quick overview of the
function without having to read the code.

### This issue

This issue is for updating the file listed in the title of the issue: FILENAME

We are using `interrogate` (a tool for checking docstrings) as follows:
`interrogate -vv -i -I -M -C -n -p FILENAME`

OUTPUT OF COMMAND ABOVE GOES HERE

You can run that locally to see if you're done, but we also recommend using
pre-commit to run pre-checks for you before submitting a pull request.
Instructions here:

https://cve-bin-tool.readthedocs.io/en/latest/CONTRIBUTING.html#using-pre-commit-to-run-linters-automatically

Or in short, go to the main cve-bin-tool directory and run the following:

```console
pip install pre-commit
pre-commit install --hook-type pre-commit --hook-type commit-msg
```


**Short tips for new contributors:**

* [cve-bin-tool's contributor docs](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md)
* If you've contributed to open source but not this project, you might just want our [checklist for a great pull request](https://github.com/intel/cve-bin-tool/blob/main/CONTRIBUTING.md#checklist-for-a-great-pull-request)
* cve-bin-tool uses <https://www.conventionalcommits.org/> style for commit messages, and we have a test that checks the title of your pull request (PR).  A good potential title for this one is in the title of this issue.
* You can make an issue auto close by including a comment "fixes #ISSUENUMBER" in your PR comments where ISSUENUMBER is the actual number of the issue.  This "links" the issue to the pull request.

**Claiming issues:**

* You do not need to have an issue assigned to you before you work on it.  To "claim" an issue either make a linked pull request or comment on the issue saying you'll be working on it.
* If someone else has already commented or opened a pull request, assume it is claimed and find another issue to work on.
* If it's been more than 1 week without progress, you can ask in a comment if the claimant is still working on it before claiming it yourself (give them at least 3 days to respond before assuming they have moved on).
