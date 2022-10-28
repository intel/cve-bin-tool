Adding a new parser to the cve-bin-tool
=======================================

In order to add a new parser to the CVE-bin-tool, one must provide a parser file. See any parser in the `parsers/` directory as an example.

Currently, a parser must provide one class which inherits Parser class of the parsers module. Class name of the parser must be same as filename that the parser parses with `Parser` suffix at the end. Ex: if you are creating a parser for `javascript` then filename of checker should be `javascript.py` and class definition should be:
```python
from cve_bin_tool.parsers import Parser

class JavascriptParser(Parser):
```

Every parser must contain a class method specific to the file you are parsing, which is:
```python
def run_checker(self, filename):
```

This `run_checker` method takes in the path of the file you are trying to parse and logic must be defined to read through the file and extract all `(product, version)` pairs from it. Each pair is then passed to `self.find_vendor(product, version)` which is another method that queries the database for the `vendor` and the result is then yielded to the output.

Once the parser is added, its name should also be added to `__init__.py` (so
that `from modules import *` will find it). 
Also a key: value pair of `filename: parser` type must also be added to `parse.py` inside `valid_files` dictionary to allow the tool to call that specific parser when that specific filename is detected.