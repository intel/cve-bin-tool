# Fuzz testing for cve-bin-tool

We're in the early stages of doing fuzz testing on cve-bin-tool, with the goal
of improving our input validation and finding potential crashes before users
do.

If you want to try it out, I have made a very simple setup for the [Atheris
fuzzer](https://github.com/google/atheris) in `fuzz/fuzz_main.py`

To install Atheris, use `pip install atheris` or you can use the fuzz-requirements.txt file I've provided (`pip install -U -r fuzz-requirements.txt`).

Once you have atheris installed, you can run the main fuzzing script yourself
from the main cve-bin-tool directory using

```console
python -m fuzz.fuzz_main
```

Right now, this won't do much, because it's just throwing garbage at the command line arguments and mostly that will return an error.  The fuzzer will need to be made smarter before we'll get really interesting crashes.

We recommend that you use a separate VM or machine for fuzz testing, as fuzzing involves sending a lot of bad data into a program and can produce unpredictable results.  This could include damage to data on your system.

Note that `virtualenv` does not provide the kind of protections you need.  Python's `virtualenv` handles default python versions and `$PYTHON_PATH` setup and whatnot for you, but does not restrict access to data on your machine.`


## Setting up for fuzzing

Setting up a VM or container is beyond the scope of this document, but if you
search for "[set up a linux
vm](https://www.google.com/search?q=set+up+a+linux+vm)" or "[set up a linux
docker
container](https://www.google.com/search?q=set+up+a+linux+docker+container)" or
similar you should be able to find what you need.

Once you have an operating system installed, you can then grab the code for cve-bin-tool and try fuzzing:

An example setup script used on Ubuntu 20.04 LTS:

```bash
#!/bin/bash

# copy ssh keys over for easier copying of data

# Get system python.  Defaulting to 3.9 for now.
# Note that this is the Ubuntu 20.04 requirements; other systems may differ
sudo apt install python3.9 python3-virtualenv cabextract python3-pip

# Prep repos for installing Bazel, required to build atheris-libprotobuf-mutator wheel
# Instructions adapted from https://docs.bazel.build/versions/5.2.0/install-ubuntu.html
sudo apt install apt-transport-https curl gnupg
curl -fsSL https://bazel.build/bazel-release.pub.gpg | gpg --dearmor > bazel.gpg
sudo apt-key add bazel.gpg
echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" | sudo tee /etc/apt/sources.list.d/bazel.list

# set up cve-bin-tool code
mkdir Code
cd Code
git clone https://github.com/intel/cve-bin-tool

# set up virtualenv
# Commented out because the atheris-libprotobuf-mutator won't install in a venv
# because the wheel build fails.
# virtualenv -p python3.9 ~/venv-fuzz/
# source ~/venv-fuzz/bin/activate

# Install cve-bin-tool & required packages
# Note that you need the cve-bin-tool install to get the checkers set up
cd cve-bin-tool
pip install -e .
pip install -U -r fuzz/fuzz-requirements.txt

# run cve-bin-tool once to get the cve data and make sure it's working
# (We may wan to fuzz the cve data gathering part later, but not now)
python -m cve_bin_tool.cli test/assets/test-curl-7.34.0.out

# actually fuzz something
python -m fuzz.fuzz_main

```
