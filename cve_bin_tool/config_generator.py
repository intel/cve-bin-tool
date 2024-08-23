# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
import json

config_header = """
# This is a generated configuration file from the CVE Binary Tool.
# Exercise caution when editing. To generate a new config file, use --generate-config option.
# For more info, refer to the official documentation at: https://cve-bin-tool.readthedocs.io/en/latest/.
# If you support the project and wish to contribute, check the Contributor Guide:
# https://cve-bin-tool.readthedocs.io/en/latest/CONTRIBUTING.html#cve-binary-tool-contributor-guide.
# Project GitHub: https://github.com/intel/cve-bin-tool
"""


def config_generator(config_format, organized_arguments):
    """
    Generate a configuration file in the specified format.

    Args:
        config_format (str): The format of the configuration file (".toml" or ".yaml").
        organized_arguments (dict): A dictionary containing organized arguments.

    Returns:
        None
    """
    if config_format == "toml":
        first_char = "["
        last_char = "]"
        sign = "="
        coma = '"'
    elif config_format == "yaml":
        first_char = ""
        last_char = ":"
        sign = ":"
        coma = ""
    else:
        return
    with open(f"config.{config_format}", "w") as f:
        f.write(f"{config_header}\n")
        for group_title, group_args in organized_arguments.items():
            if group_title == "positional_arguments":
                continue
            group_title = group_title.lower()
            if group_title == "output":
                if group_args["sbom-output"]["arg_value"] == "":
                    group_args["sbom-type"]["arg_value"] = None
                    group_args["sbom-format"]["arg_value"] = None
                    group_args["sbom-output"]["arg_value"] = None
            if group_title == "vex_output":
                if group_args["vex-output"]["arg_value"] == "":
                    group_args["vex-type"]["arg_value"] = None
                    group_args["vex-output"]["arg_value"] = None
            f.write(f"{first_char}{group_title}{last_char}\n")
            for arg_name, arg_value_help in group_args.items():
                arg_value = arg_value_help["arg_value"]
                arg_help = arg_value_help["help"]
                arg_name = arg_name.replace("-", "_")
                if arg_name in ["config", "generate_config"]:
                    arg_value = None
                if "\n" in arg_help:
                    arg_help = arg_help.replace("\n", "  ")
                if arg_value in [True, False] or isinstance(arg_value, list):
                    arg_val = (
                        json.dumps(arg_value).lower()
                        if arg_value in [True, False]
                        else arg_value
                    )
                    f.write(f"  # {arg_help}\n" f"  {arg_name} {sign} {arg_val}\n\n")
                elif arg_value is not None:
                    f.write(
                        f"  # {arg_help}\n"
                        f"  {arg_name} {sign} {coma}{arg_value}{coma}\n\n"
                    )
