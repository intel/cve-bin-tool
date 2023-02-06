import re
from importlib.metadata import version

new_pins = {"pre-commit": version("pre-commit")}
pre_commit_path = ".pre-commit-config.yaml"
with open(pre_commit_path) as f:
    tools = f.read().split("repo")
for tool in tools:
    package_match = re.search("id: (.*)", tool)
    if not package_match:
        continue
    version_match = re.search("rev: (.*)", tool)
    if not version_match:
        continue
    new_pins[package_match.group(1).lstrip()] = version_match.group(1).lstrip()

requirements_path = "dev-requirements.txt"
with open(requirements_path) as f:
    tools = f.readlines()
for ind, tool in enumerate(tools):
    package_match = re.search("(.*)==(.*)", tool)
    if not package_match:
        continue
    package_name = package_match.group(1)
    if package_name in new_pins:
        if ";" in tool:
            tools[ind] = re.sub("==(.*);", f"=={new_pins[package_name]};", tool)
        else:
            tools[ind] = re.sub("==(.*)", f"=={new_pins[package_name]}", tool)
with open(requirements_path, "w") as f:
    f.writelines(tools)
