CVE Binary Tool Contributor Guide
=================================

The CVE Binary Tool team participates in a few events every year that are aimed at new people in open source.  This guide is meant to help people get over the initial hurdle of figuring out how to use git and make a contribution.

If you've already contributed to other open source projects, contributing to the CVE Binary Tool project should be pretty similar and you can probably figure it out by guessing.  But if you've never contributed to anything before, or you just want to see what we consider best practice before you start, this is the guide for you!



Getting and maintaining a local copy of the source code
-------------------------------------------------------

There are lots of different ways to use git, and it's so easy to get into a messy state that [there's a comic about it](https://xkcd.com/1597/).  So... if you get stuck, remember, even experieneced programmers somtimes just delete their trees and copy over the stuff they want manually.  

If you're planning to contribute, first you'll want to [get a local copy of the source code (also known as "cloning the repository")](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/cloning-a-repository)

`git clone git@github.com:intel/cve-bin-tool.git`

Once you've got the copy, you can update it using

`git pull`

Git allows you to have "branches" with variant versions of the code.  You can see what's available using `git branch` and switch to one using `git checkout branch_name`. 

To make your life easier, we recommend that the `master` branch always be kept in sync with the repo at `https://github.com/intel/cve-bin-tool`, as in you never check in any code to that branch.


Setting up your personal fork
-----------------------------

To make a fork on github, read the instructions at [Fork a repo](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)


## Style Guide for cve-bin-tool
This list contains all the style guide that one must follow while contributing so that code is consistent and maintaiable.

### String Formatting
Python provide many different ways to format the string(you can read about them [here](https://realpython.com/python-formatted-output/))and we use f-string formatting in our tool.

**Note: As f-strings are only supported in python 3.6+. Please make sure you have version >=3.6** 

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

### Style Format
CVE Binary Tool uses Black as the style formatter. Contributors are requested to format their code with Black before submitting.

####  Installing Black
Black can be easily installed with the help of pip. 
```bash
$ pip install black
```  

#### Formatting Code
Formatting a file is easy. Just navigate to the file and run the following command. For formatting a particular file name filename.py.
```bash
$ black filename.py
```
But in real life you might want to format each file in a particular folder. 
```bash
$ cd Code/
$ black ./
```
In my case the name of the folder is Code. First navigate to the folder and then use black on the folder using  ```./``` 

