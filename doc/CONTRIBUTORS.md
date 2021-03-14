# CVE Binary Tool Contributor Guide

The CVE Binary Tool team participates in a few events every year that are aimed at new people in open source.  This guide is meant to help people get over the initial hurdle of figuring out how to use git and make a contribution.

If you've already contributed to other open source projects, contributing to the CVE Binary Tool project should be pretty similar and you can probably figure it out by guessing.  But if you've never contributed to anything before, or you just want to see what we consider best practice before you start, this is the guide for you!

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

`git remote add myfork git@github.com/MYUSERNAME/cve-bin-tool.git`

Replace MYUSERNAME with your own GitHub username.

## Setting up a virtualenv

This section isn't required, but many contributors find it helpful, especially for running tests using different versions of python.

[virtualenv](https://virtualenv.pypa.io/en/latest/) is a tool for setting up virtual python environments.  This allows you to have all the dependencies for cve-binary-tool set up in a single environment, or have different environments set up for testing using different versions of Python.  

To install it:

```bash
pip install virtualenv
```

To make a new venv using python 3.8:

```bash
virtualenv -p python3.8 ~/Code/venv3.8
```

Each time you want to use a virtualenv, you "activate" it using the activate script:

```bash
source ~/Code/venv3.8/bin/activate
```

And when you're done with the venv, you can deactivate it using the `deactivate` command.

While you're in a venv, the `python` command will point to whatever version you specified when the venv was created, and pip command will install things only in that venv so you don't have to worry about conflicts with other versions or system packages.  

## Installing dependencies

The packages you need to run CVE Binary Tool are listed in the `requirements.txt` file in the main cve-bin-tool directory.  You can install all of them using the following pip command.

```bash
pip install -r requirements.txt
```

## Running tests

The CVE Binary Tool has a set of tests that can be run using `pytest` command.  Usually all the short tests should pass, although sometimes internet connectivity issues will cause problems.

[There is a README file in the tests directory](https://github.com/intel/cve-bin-tool/blob/main/test/README.md) which contains more info about how to run just specific tests, or how to run the longer tests which involve downloading full software packages to test the tool. The long tests sometimes fail due to package name changes, which may not be your fault unless you modified one of them.

## Running isort and black

CVE Binary Tool uses isort to sort imports alphabetically, and automatically separated into sections and by type. We also use Black as style formatter. Contributors are requested to format their code with isort and black before submitting, and the CI will warn you if your
code needs re-formatting.

isort can be installed using pip.

```bash
pip install isort
```  

Black can be installed using pip.

```bash
pip install black
```  
To format the imports using isort, you run `isort --profile black` followed by the filename. You will have to add `--profile black` when calling isort to make it compatible with Black formatter. For formatting a particular file name filename.py.

```bash
isort --profile black filename.py
```
Alternatively, you can run isort recursively for all the files by adding `.` instead of filename

```bash
isort --profile black .
```
To format the code, you run `black` followed by the filename you wish to reformat.  For formatting a particular file name filename.py.

```bash
black filename.py
```

In many cases, it will make your life easier if you only run black on
files you've changed because you won't have to scroll through a pile of
auto-formatting changes to find your own modifications.  However, you can also
specify a whole folder using ```./```

### Using pre-commit to run isort and Black

We've provided a pre-commit hook (in `.pre-commit.config.yaml`) so if you want
to run isort/Black locally before you commit, you can install pre-commit and install
the hook as follows from the main cve-bin-tool directory:

```bash
pip install pre-commit
pre-commit install
```

## Making a new branch & pull request

Git allows you to have "branches" with variant versions of the code.  You can see what's available using `git branch` and switch to one using `git checkout branch_name`.

To make your life easier, we recommend that the `main` branch always be kept in sync with the repo at `https://github.com/intel/cve-bin-tool`, as in you never check in any code to that branch.  That way, you can use that "clean" main branch as a basis for each new branch you start as follows:

```bash
git checkout main
git pull
git checkout -b my_new_branch
```

When you're ready to share that branch to make a pull request, make sure you've checked in all the files you're working on.  You can get a list of the files you modified using `git status` and see what modifications you made using `git diff`

Use `git add FILENAME` to add the files you want to put in your pull request, and use `git commit` to check them in.  Try to use [a clear commit message](https://chris.beams.io/posts/git-commit/).  We usually merge pull requests into a single commit when we accept them, so it's fine if you have lots of commits in your branch while you figure stuff out.

Once your branch is ready and you've checked in all your code, push it to your fork:

```bash
git push myfork
```

From there, you can go to [our pull request page](https://github.com/intel/cve-bin-tool/pulls) to make a new pull request from the web interface.

## Code Review

Once you have created a pull request (PR), GitHub Actions will try to run all the tests on your code.  If you can, make any modifications you need to make to ensure that they all pass, but if you get stuck a reviewer will see if they can help you fix them.  Remember that you can run the tests locally while you're debugging; you don't have to wait for GitHub to run the tests (see the [Running tests](#running-tests) section above for how to run tests).

Someone will review your code and try to provide feedback in the comments on GitHub.  Usually it takes a few days, sometimes up to a week.  The core contributors for this project work on it as part of their day jobs and are usually on US Pacific time, so you might get an answer a bit faster during their work week.

If something needs fixing or we have questions, we'll work back and forth with you to get that sorted.  We usually do most of the chatting directly in the pull request comments on GitHub, but if you're stuck you can also stop by our [Gitter chat room](https://gitter.im/cve-bin-tool/community) to talk with folk outside of the bug.

Once any issues are resolved, we'll merge your code.  Yay!

In rare cases, the code won't work for us and we'll let you know.  Sometimes this happens because someone else has already submitted a fix for the same bug, (Issues marked [good first issue](https://github.com/intel/cve-bin-tool/labels/good%20first%20issue) can be in high demand!) or because you worked on a checker that didn't have a good signature. Don't worry, these things happens, no one thinks less of you for trying!

## Style Guide for cve-bin-tool

This list contains all the style guide that one must follow while contributing so that code is consistent and maintainable.

### String Formatting

Python provides many different ways to format the string(you can read about them [here](https://realpython.com/python-formatted-output/))and we use f-string formatting in our tool.

**Note: As f-strings are only supported in python 3.6+.** Please make sure you have version >=3.6

- **Example:** Formatting string using f-string

```python
#Program prints a string containing name and age of person
name = "John Doe"
age = 23
print(f"Name of the person is {name} and his age is {age}")

#Output
# "Name of the person is John Doe and his age is 23"
```

Note that the string started with the **'f'** followed by the string. Values are always added in the curly braces. Also we don't need to convert age into string. (we may have used **str(age )** before using it in the string) f-strings are useful as they provide many cool features. You can read more about features and the good practices to use f-strings [here](https://realpython.com/python-f-strings/#f-strings-a-new-and-improved-way-to-format-strings-in-python).

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
4. Suggest fixes for documentaiton.  If you try some instruction and it doesn't work, or you notice a typo, those are always easy first commits!  One place we're a bit weak is instructions for Windows users.

If you get stuck or find something that you think should work but doesn't, ask for help in an issue or stop by [the cve-bin-tool gitter](https://gitter.im/cve-bin-tool/community) to ask questions.

Note that our "good first issue" bugs are in high demand during the February-April due to the start of Google Summer of Code.  It's totally fine to comment on a bug and say you're interested in working on it, but if you don't actually have any pull request with a tentative fix up within a week or so, someone else may pick it up and finish it. If you want to spend more time thinking, the new checkers (especially ones no one has asked for) might be a good place for a relaxed first commit.
