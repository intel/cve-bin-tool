# CVE Binary Tool Contributor Guide

The CVE Binary Tool team participates in a few events every year that are aimed at new people in open source.  This guide is meant to help people get over the initial hurdle of figuring out how to use git and make a contribution.

If you've already contributed to other open source projects, contributing to the CVE Binary Tool project should be pretty similar and you can probably figure it out by guessing.  Experienced contributors might want to just skip ahead to the [checklist for a great pull request](#checklist-for-a-great-pull-request)  But if you've never contributed to anything before, or you just want to see what we consider best practice before you start, this is the guide for you!

- [CVE Binary Tool Contributor Guide](#cve-binary-tool-contributor-guide)
  - [Imposter syndrome disclaimer](#imposter-syndrome-disclaimer)
  - [Code of Conduct](#code-of-conduct)
  - [Development Environment](#development-environment)
  - [Getting and maintaining a local copy of the source code](#getting-and-maintaining-a-local-copy-of-the-source-code)
  - [Choosing a version of python](#choosing-a-version-of-python)
  - [Setting up a virtualenv](#setting-up-a-virtualenv)
  - [Installing dependencies](#installing-dependencies)
  - [Running your local copy of CVE Binary Tool](#running-your-local-copy-of-cve-binary-tool)
  - [Help, my checkers aren't loading](#help-my-checkers-arent-loading)
  - [Running tests](#running-tests)
  - [Running linters](#running-linters)
    - [Using pre-commit to run linters automatically](#using-pre-commit-to-run-linters-automatically)
    - [Running isort by itself](#running-isort-by-itself)
    - [Running black by itself](#running-black-by-itself)
    - [Running bandit by itself](#running-bandit-by-itself)
    - [Running mypy by itself](#running-mypy-by-itself)
    - [Running interrogate by itself](#running-interrogate-by-itself)
    - [Other linting tools](#other-linting-tools)
  - [Making a new branch \& pull request](#making-a-new-branch--pull-request)
    - [Commit message tips](#commit-message-tips)
    - [Sharing your code with us](#sharing-your-code-with-us)
    - [Checklist for a great pull request](#checklist-for-a-great-pull-request)
  - [Code Review](#code-review)
  - [Style Guide for cve-bin-tool](#style-guide-for-cve-bin-tool)
    - [String Formatting](#string-formatting)
  - [Making documentation](#making-documentation)
  - [Where should I start?](#where-should-i-start)
    - [Claiming an issue](#claiming-an-issue)

## Imposter syndrome disclaimer

_We want your help_. No really, we do.

There might be a little voice inside that tells you you're not ready; that you need to do one more tutorial, or learn another framework, or write a few more blog posts before you can help with this project.

I assure you, that's not the case.

This document contains some contribution guidelines and best practices, but if you don't get it right the first time we'll try to help you fix it.

The contribution guidelines outline the process that you'll need to follow to get a patch merged. By making expectations and process explicit, we hope it will make it easier for you to contribute.

And you don't just have to write code. You can help out by writing documentation, tests, or even by giving feedback about this work. (And yes, that includes giving feedback about the contribution guidelines.)

If have questions or want to chat, we have a [gitter chat room](https://gitter.im/cve-bin-tool/community) where you can ask questions, or you can put them in [GitHub issues](https://github.com/intel/cve-bin-tool/issues) too.

Thank you for contributing!

This section is adapted from [this excellent document from @adriennefriend](https://github.com/adriennefriend/imposter-syndrome-disclaimer)

## Code of Conduct

CVE Binary Tool contributors are asked to adhere to the [Python Community Code of Conduct](https://www.python.org/psf/conduct/).  Please contact [Terri](https://github.com/terriko/) if you have concerns or questions relating to this code of conduct.

Note: The Python Community Code of Conduct is a required part of our participation in
Google Summer of Code as a sub-org with the Python Software Foundation.

## Development Environment

Linux is the preferred operating system to use while contributing to CVE Binary Tool. If you're using Windows, we recommend setting up [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10).

## Getting and maintaining a local copy of the source code

There are lots of different ways to use git, and it's so easy to get into a messy state that [there's a comic about it](https://xkcd.com/1597/).  So... if you get stuck, remember, even experienced programmers sometimes just delete their trees and copy over the stuff they want manually.

If you're planning to contribute, first you'll want to [get a local copy of the source code (also known as "cloning the repository")](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)

`git clone git@github.com:intel/cve-bin-tool.git`

Once you've got the copy, you can update it using

`git pull`

You're also going to want to have your own "fork" of the repository on GitHub.
To make a fork on GitHub, read the instructions at [Fork a
repo](https://help.github.com/en/github/getting-started-with-github/fork-a-repo).
A fork is a copy of the main repository that you control, and you'll be using
it to store and share your code with others.  You only need to make the fork once.

Once you've set up your fork, you will find it useful to set up a git remote for pull requests:

`git remote add myfork git@github.com:MYUSERNAME/cve-bin-tool.git`

Replace MYUSERNAME with your own GitHub username.

## Choosing a version of python

CVE Binary Tool supports [any version of python that has ongoing security support](https://endoflife.date/python).  There can be a bit of lag before we enable a new release or fully disable an old one.  If you don't need multiple versions of python for a specific bug, we recommend starting with either the most recent version of python or the one before (e.g. the first or second thing on [the "Active Python Releases" list](https://www.python.org/downloads/)).

Note that some of our [linters](#running-linters) (tools used to help with code quality) may not work on the oldest version of python.  That's the last one on [the "Active Python Releases" list](https://www.python.org/downloads/).  So if you're doing development on the oldest version of python, for best results you should switch to a newer version before you run linters on your code or do a `git commit`.

## Setting up a virtualenv

This section isn't required, but many contributors find it helpful, especially for running tests using different versions of python.

[virtualenv](https://virtualenv.pypa.io/en/latest/) is a tool for setting up virtual python environments.  This allows you to have all the dependencies for cve-bin-tool set up in a single environment, or have different environments set up for testing using different versions of Python.

To install it:

```bash
pip install virtualenv
```

To make a new venv using python 3.11:

```bash
virtualenv -p python3.11 ~/Code/venv3.11
```

Each time you want to use a virtualenv, you "activate" it using the activate script:

```bash
source ~/Code/venv3.11/bin/activate
```

And when you're done with the venv, you can deactivate it using the `deactivate` command.

While you're in a venv, the `python` command will point to whatever version you specified when the venv was created, and pip command will install things only in that venv so you don't have to worry about conflicts with other versions or system packages.  

## Installing dependencies

The packages you need to run CVE Binary Tool are listed in the `requirements.txt` file in the main cve-bin-tool directory.  You can install all of them using the following pip command:

```bash
pip install -U -r requirements.txt
```

The `-U` in that line above will update you to the latest versions of packages as needed, which we recommend because people running security tools generally want to have all the latest updates if possible. The `-r requirements.txt` specifies the file with all the requirements.

We also have a recommended list of dependencies just for developers that include things like the flake8 linter.  You probably want to install them too if you're intending to be a developer.

```bash
pip install -r dev-requirements.txt
```

## Running your local copy of CVE Binary Tool

One of the reasons we suggest virtualenv is that it makes it easier to do this section.

If you want to run a local copy of cve-bin-tool, the recommended way is to install it locally.  From the cve-bin-tool main directory, run:

### If not in a virtual environment
```bash
python3 -m pip install --user -e .
```

### If in a virtual environment
```bash
python3 -m pip install -e .
```

Then you can type `cve-bin-tool` on the command line and it will do the right thing.  This includes some special code intended to deal with adding new checkers to the list on the fly so things should work seamlessly for you while you're building new contributions.

## Help, my checkers aren't loading

CVE Binary Tool uses the installed egg file to figure out which checkers are installed. If you run it directly without installing it (e.g. you try to use `python -m cve_bin_tool.cli`), it will usually work fine but you may occasionally find that checkers aren't loading properly.  Typically this happens with new checkers you are adding, but sometimes if you `git pull` it will cause a similar effect.  If you get into this state, you can fix it by running the following command from the main cve-bin-tool directory:

```bash
python setup.py egg_info
```

We recommend that you switch to having a local install to avoid this problem in the future. 

Run the following in the main `cve-bin-tool` directory:

### If not in a virtual environment
```bash
pip install --user -e .
```

### If in a virtual environment
```bash
pip install -e .
```

## Running tests

The CVE Binary Tool has a set of tests that can be run using `pytest` command.  Typically you want to run `pytest` in the cve-bin-tool directory to run the short test suite and make sure tests pass.

After running `pytest`, you may get several test failures relating to `ModuleNotFound` error. If you have run `pip install -r dev-requirements.txt` or equivalent and are sure you have the required modules installed, your issue may be related to Python's module search path. You can run this command instead :

```bash
python -m pytest
```

This bypasses potential issues with your system's PATH environment variable, potentially looking in the wrong directory for the dependencies.

[There is a README file in the tests directory](https://github.com/intel/cve-bin-tool/blob/main/test/README.md) which contains more info about how to run specific tests, or how to run the longer tests.

We have done our best to make tests stable and ensure that they pass at all times, but occasionally tests may fail due to factors outside your control (common causes: internet connectivity, rate limiting by NVD or new vulnerability data changing our test expectations). If a test doesn't pass, you should look at it to see if any changes you made caused the failure.  If you're not sure, submit your code as a pull request and mention the issue and someone will try to help you sort it out.

When you submit your code as a pull request, the whole test suite will be run on windows and linux using the versions of python we support, including longer tests. We don't expect you to do all that yourself; usually trying for one version of python on whatever local OS you have is good enough and you can let GitHub Actions do the rest!

## Running linters

CVE Binary Tool uses a few tools to improve code quality and readability:

- `isort` sorts imports alphabetically and by type
- `black` provides automatic style formatting.  This will give you basic [PEP8](https://www.python.org/dev/peps/pep-0008/) compliance. (PEP8 is where the default python style guide is defined.)
- `flake8` provides additional code "linting" for more complex errors like unused imports.
- `pyupgrade` helps us be forward compatible with new versions of python.
- `bandit` is more of a static analysis tool than a linter and helps us find potential security flaws in the code.
- `gitlint` helps ensure that the commit messages follow [Conventional Commits](https://conventionalcommits.org).
- `mypy` helps ensure type definitions are correct when provided.
- `interrogate` checks your code base for missing docstrings.

We provide a `dev-requirements.txt` file which includes all the precise versions of tools as they'll be used in GitHub Actions.  You an install them all using pip:

```bash
pip install -r dev-requirements.txt
```

### Using pre-commit to run linters automatically

We've provided a pre-commit hook (in `.pre-commit.config.yaml`) so if you want
to run isort/Black locally before you commit, you can install
the hook as follows from the main `cve-bin-tool` directory:

```bash
pre-commit install --hook-type pre-commit --hook-type commit-msg
```

Once this is installed, all of those commands will run automatically when you run `git commit` and it won't let you commit until any issues are resolved.  (You can also run them manually using `pre-commit` with no arguments.) This will only run on files staged for commit (e.g. things where you've already run `git add`).  If you want to run on arbitrary files, see below:

### Running isort by itself

To format the imports using isort, you run `isort --profile black` followed by the filename. You will have to add `--profile black` when calling isort to make it compatible with Black formatter. For formatting a particular file name filename.py.

```bash
isort --profile black filename.py
```

Alternatively, you can run isort recursively for all the files by adding `.` instead of filename

```bash
isort --profile black .
```

### Running black by itself

To format the code, you run `black` followed by the filename you wish to reformat.  For formatting a particular file name filename.py.

```bash
black filename.py
```

In many cases, it will make your life easier if you only run black on
files you've changed because you won't have to scroll through a pile of
auto-formatting changes to find your own modifications.  However, you can also
specify a whole folder using ```./```

### Running bandit by itself

We have a configuration file for bandit called `bandit.conf` that you should use.  This disables a few of the checkers.

To run it on all the code we scan, use the following:

```bash
bandit -c bandit.conf -r cve_bin_tool/ test/
```

You can also run it on individual files:

```bash
bandit -c bandit.conf filename.py
```

If you run it without the config file, it will run a few extra checkers, so you'll get additional warnings.

Bandit helps you target manual code review, but bandit issues aren't always things that need to be fixed, just reviewed.  If you have a bandit finding that doesn't actually need a fix, you can mark it as reviewed using a `# nosec` comment.  If possible, include details as to why the bandit results are ok for future reviewers.  For example, we have comments like `#nosec uses static https url above` in cases where bandit prompted us to review the variable being passed to urlopen().

### Running mypy by itself

To check for static type checking, you run `mypy` followed by the filename you wish to check static type for. mypy checks the type annotations you provide and reports any type mismatches or missing annotations. For static type checking for a particular file name filename.py

```bash
mypy filename.py
```

Alternatively, you can run mypy on directory as well. For static type checking for a directory

```bash
mypy cve_bin_tool/
```

for someone who is new or are not familiar to python typing here are few resource - 
[mypy documentation](https://mypy.readthedocs.io/en/stable/index.html), [resource for more understanding](https://www.linode.com/docs/guides/python-static-type-checking-with-mypy/) and its [Quick reference](https://mypy.readthedocs.io/en/stable/cheat_sheet_py3.html) and [Python typing documentation](https://docs.python.org/3/library/typing.html)

### Running interrogate by itself

`interrogate` is a tool designed to enhance code documentation by identifying missing docstrings within your Python codebase. `interrogate` will tell you which methods, functions, classes, and modules have docstrings, and which do not.

When running `interrogate`, you need to specify the path to the directory or files that you want to check for missing docstrings. 

```bash
interrogate [PATH]
```

In pre-commit, we use the following flags: 
* `-vv` makes interrogate print a report with all relevant functions showing which ones have or are missing docstrings
* `-i` and `-I` ignore __init__ functions and __init__.py files (because writing "initializes $class" repeatedly is boring)
* The flags `-M`, `-n`, `-c` and `-p` exclude other types of functions.  These are intended to reduce the scope of the problem and help us focus on filling in the most important docstrings first.
* The `-e` flag in interrogate is used to exclude specific files or directories from analysis.
* The `-f` flag in interrogate is employed to specify a minimum coverage percentage, and the tool will result in failure if the actual coverage falls below this designated threshold. 

To run exactly what you'll get when pre-commit runs, you can use the following:
```
interrogate -vv -i -I -M -C -n -p -f 60.0 -e fuzz/ -e test/ -e cve_bin_tool/checkers/ -e build/
```
You can specify a file or directory if you just want to check the files you changed.  

Interrogate shows some [report examples in their docs](https://interrogate.readthedocs.io/en/latest/#usage) or you can look at the [current cve-bin-tool reports in our linter runs on GitHub Actions](https://github.com/intel/cve-bin-tool/actions/workflows/linting.yml)

### Other linting tools

As well as `black` for automatically making sure code adheres to the style guide, we use `flake8` to help us find things like unused imports.  The [flake8 documentation](https://flake8.pycqa.org/en/latest/user/index.html) covers what you need to know about running it.

We use [pyupgrade](https://github.com/asottile/pyupgrade) to make sure our syntax is updated to fit new versions of python.

We also have a spell checker set up to help us avoid typos in documentation.  The [spelling actions readme file](https://github.com/intel/cve-bin-tool/tree/main/.github/actions/spelling) gives more information including how to add new words to the dictionary if needed.

We also have a tool to help make sure that new checkers are added to the tables in our documentation and relevant words associated with checker names are put in allow dictionary for spelling checks, this is done automatically with GitHub actions. [The format_checkers code is here](https://github.com/intel/cve-bin-tool/blob/main/cve_bin_tool/format_checkers.py), if you're curious.

You can view all the config files for GitHub Actions (what we use for Continuous Integration (CI)) in [the .github/workflows directory](https://github.com/intel/cve-bin-tool/tree/main/.github/workflows).

## Making a new branch & pull request

Git allows you to have "branches" with variant versions of the code.  You can see what's available using `git branch` and switch to one using `git checkout branch_name`.

To make your life easier, we recommend that the `main` branch always be kept in sync with the repo at `https://github.com/intel/cve-bin-tool`, as in you never check in any code to that branch.  That way, you can use that "clean" main branch as a basis for each new branch you start as follows:

```bash
git checkout main
git pull
git checkout -b my_new_branch
```

>Note: If you accidentally check something in to main and want to reset it to match our main branch, you can save your work using `checkout -b` and then do a `git reset` to fix it:
>```bash
>git checkout -b saved_branch
>git reset --hard origin/main
>```
>You do not need to do the `checkout` step if you don't want to save the changes you made.

When you're ready to share that branch to make a pull request, make sure you've checked in all the files you're working on.  You can get a list of the files you modified using `git status` and see what modifications you made using `git diff`

Use `git add FILENAME` to add the files you want to put in your pull request, and use `git commit` to check them in.  Try to use [a clear commit message](https://chris.beams.io/posts/git-commit/) and use the [Conventional Commits](https://www.conventionalcommits.org/) format.  

### Commit message tips

We usually merge pull requests into a single commit when we accept them, so it's fine if you have lots of commits in your branch while you figure stuff out, and we can fix your commit message as needed then.  But if you make sure that at least the title of your pull request follows the [Conventional Commits](https://www.conventionalcommits.org/) format that you'd like for that merged commit message, that makes our job easier!

GitHub also has some keywords that help us link issues and then close them automatically when code is merged.  The most common one you'll see us use looks like `fixes: #123456`. You can put this in the title of your PR (what usually becomes the commit message when we merge your code), another line in the commit message, or any comment in the pull request to make it work.  You and read more about [linking a pull request to an issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) in the GitHub documentation.

### Sharing your code with us

Once your branch is ready and you've checked in all your code, push it to your fork:

```bash
git push myfork
```

From there, you can go to [our pull request page](https://github.com/intel/cve-bin-tool/pulls) to make a new pull request from the web interface.

### Checklist for a great pull request

Here's a quick checklist to help you make sure your pull request is ready to go:

1. Have I run the tests locally on at least one version of Python?
   - Run the command `pytest` (See also [Running Tests](#running-tests))
   - GitHub Actions will run the tests for you, but you can often find and fix issues faster if you do a local run of the tests.
2. Have I run the code linters and fixed any issues they found?
   - We recommend setting up `pre-commit` so these are run automatically (See also [Running Linters](#running-linters))
   - GitHub Actions will run the linters for you too if you forget! (And don't worry, even experienced folk forget sometimes.)
   - You will be responsible for fixing any issue found by the linters before your code can be merged.
3. Have I added any tests I need to prove that my code works?
   - This is especially important for new features or new checkers.
4. Have I added or updated any documentation if I changed or added a feature?
   - New features are often documented in [MANUAL.md](https://github.com/intel/cve-bin-tool/blob/main/doc/MANUAL.md).  (See [Making documentation](#making-documentation) for more information.)
5. Have I used [Conventional Commits](https://www.conventionalcommits.org/) to format the title of my pull request?
6. If I closed a bug, have I linked it using one of [GitHub's keywords](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)? (e.g. include the text `fixed #1234`)
7. Have I checked on the results from GitHub Actions?
   - GitHub Actions will run all the tests, linters and a spell check for you.  If you can, try to make sure everything is running cleanly with no errors before leaving it for a human code reviewer!
   - As of this writing, tests take less than 20 minutes to run once they start, but they can be queued for a while before they start.  Go get a cup of tea or work on something else while you wait!

## Code Review

Once you have created a pull request (PR), GitHub Actions will try to run all the tests on your code.  If you can, make any modifications you need to make to ensure that they all pass, but if you get stuck a reviewer will see if they can help you fix them.  Remember that you can run the tests locally while you're debugging; you don't have to wait for GitHub to run the tests (see the [Running tests](#running-tests) section above for how to run tests).

Someone will review your code and try to provide feedback in the comments on GitHub.  Usually it takes a few days, sometimes up to a week.  The core contributors for this project work on it as part of their day jobs and are usually on US Pacific time, so you might get an answer a bit faster during their work week.

If something needs fixing or we have questions, we'll work back and forth with you to get that sorted.  We usually do most of the chatting directly in the pull request comments on GitHub, but if you're stuck you can also stop by our [Gitter chat room](https://gitter.im/cve-bin-tool/community) to talk with folk outside of the bug.

>Another useful tool is `git rebase`, which allows you to change the "base" that your code uses.  We most often use it as `git rebase origin/main` which can be useful if a change in the main tree is affecting your code's ability to merge.  Rebasing is a bit much for an intro document, but [there's a git rebase tutorial here](https://www.atlassian.com/git/tutorials/rewriting-history/git-rebase) that you may find useful if it comes up.

Once any issues are resolved, we'll merge your code.  Yay!

In rare cases, the code won't work for us and we'll let you know.  Sometimes this happens because someone else has already submitted a fix for the same bug, (Issues marked [good first issue](https://github.com/intel/cve-bin-tool/labels/good%20first%20issue) can be in high demand!) or because you worked on a checker that didn't have a good signature. Don't worry, these things happens, no one thinks less of you for trying!

## Style Guide for cve-bin-tool

Most of our "style" stuff is caught by the `black` and `flake8` linters, but we also recommend that contributors use f-strings for formatted strings:

### String Formatting

Python provides many different ways to format the string (you can read about them [here](https://realpython.com/python-formatted-output/)) and we use f-string formatting in our tool.

> Note: f-strings are only supported in python 3.6+.

- **Example:** Formatting string using f-string

```python
#Program prints a string containing name and age of person
name = "John Doe"
age = 23
print(f"Name of the person is {name} and his age is {age}")

#Output
# "Name of the person is John Doe and his age is 23"
```

Note that the string started with the `f` followed by the string. Values are always added in the curly braces. Also we don't need to convert age into string. (we may have used `str(age)` before using it in the string) f-strings are useful as they provide many cool features. You can read more about features and the good practices to use f-strings [here](https://realpython.com/python-f-strings/#f-strings-a-new-and-improved-way-to-format-strings-in-python).

## Making documentation

The documentation for CVE Binary Tool can be found in the `doc/` directory (with the exception of the README.md file, which is stored in the main directory but linked in the documentation directory for convenience).

Like many other Python-based projects, CVE Binary Tool uses Sphinx and
ReadTheDocs to format and display documentation. If you're doing more than minor typo
fixes, you may want to install the relevant tools to build the docs.  There's a
`requirements.txt` file available in the `doc/` directory you can use to install
sphinx and related tools:

```bash
cd doc/
pip install -r requirements.txt
```

Once those are installed, you can build the documentation using `make` in the
docs directory:

```bash
make docs
```

or use sphinx-build directly with the following options:

```bash
sphinx-build -b html . _build
```

That will build the HTML rendering of the documentation and store it in the
`_build` directory.   You can then use your web browser to go to that
directory and see what it looks like.

Note that you don't need to commit anything in the `_build` directory.  Only the `.md` and `.rst` files should be checked in to the repository.

If you don't already have an editor that understands Markdown (`.md`) and
RestructuredText (.`rst`) files, you may want to try out Visual Studio Code, which is free and has a nice Markdown editor with a preview.

## Where should I start?

Many beginners get stuck trying to figure out how to start.  You're not alone!

Here's three things we recommend:

1. Try something marked as a "[good first issue](https://github.com/intel/cve-bin-tool/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)" We try to mark issues that might be easier for beginners.
2. [Add tests to an existing checker](https://github.com/intel/cve-bin-tool/blob/main/test/README.md). This will give you some practice with the test suite.
3. [Add a new checker](https://github.com/intel/cve-bin-tool/blob/main/cve_bin_tool/checkers/README.md)  This will give you some deeper understanding of how the tool works and what a signature looks like.  We have a few new checker requests listed in the "good first issue" list, or any linux library that has known CVEs (preferably recent ones) is probably interesting enough.
4. Suggest fixes for documentation.  If you try some instruction and it doesn't work, or you notice a typo, those are always easy first commits!  One place we're a bit weak is instructions for Windows users.

If you get stuck or find something that you think should work but doesn't, ask for help in an issue or stop by [the cve-bin-tool gitter](https://gitter.im/cve-bin-tool/community) to ask questions.

Note that our "good first issue" bugs are in high demand during the February-April due to the start of Google Summer of Code.  It's totally fine to comment on a bug and say you're interested in working on it, but if you don't actually have any pull request with a tentative fix up within a week or so, someone else may pick it up and finish it. If you want to spend more time thinking, the new checkers (especially ones no one has asked for) might be a good place for a relaxed first commit.

### Claiming an issue

- You do not need to have an issue assigned to you before you work on it.  To "claim" an issue either make a linked pull request or comment on the issue saying you'll be working on it.  
- If someone else has already commented or opened a pull request, assume it is claimed and find another issue to work on.  
- If it's been more than 1 week without progress, you can ask in a comment if the claimant is still working on it before claiming it yourself (give them at least 3 days to respond before assuming they have moved on).

The reason we do it this way is to free up time for our maintainers to do more code review rather than having them handling bug assignment.  This is especially important to help us function during busy times of year when we take in a large number of new contributors such as Hacktoberfest (October) and the beginning of Google Summer of Code (January-April).
