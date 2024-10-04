import argparse
import sys
import textwrap


def generate_out(text):
    print(text)


argv = sys.argv
app_name = "pytestgen"
parser = argparse.ArgumentParser(
    prog=app_name,
    description=textwrap.dedent(
        """
        Generates pytest skeleton for a Python class.
        """
    ),
)
parser.add_argument(
    "-o",
    "--output-file",
    action="store",
    default="",
    help="output filename (default: output to stdout)",
)
parser.add_argument("-V", "--version", action="version", version="0.1")
parser.add_argument("FILE", help="python source file")

raw_args = parser.parse_args(argv[1:])
args = {key: value for key, value in vars(raw_args).items() if value}

filename = args["FILE"]

with open(filename) as f:
    lines = f.readlines()
for line in lines:
    line = line.strip()
    if line.startswith("class"):
        classname = filename.replace(".py", "").capitalize()
        generate_out("import pytest\n")
        generate_out("import <module> as test_module\n")
        generate_out(f"class Test{classname}:\n")
    elif line.startswith("def") and "__init__" not in line:
        # Generate test function
        function = line.split(" ")[1].split("(")[0]
        generate_out(f"\tdef test_{function}(self):")
        if function.startswith("set"):
            attribute = function.replace("set_", "")
            generate_out("\t\ttest_item = test_module()")
            generate_out(f"\t\ttest_item.{function}('test_{attribute}')")
            generate_out(
                f"\t\tassert test_item.get_value('{attribute}') == 'test_{attribute}'\n\n"
            )
        else:
            generate_out("\t\tassert False\n\n")
