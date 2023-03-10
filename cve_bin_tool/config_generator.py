class config_generator:
    def config_generator(args, types):
        if types == "toml":
            first_char = "["
            last_char = "]"
            sign = "="
            coma = '"'
        elif types == "yaml":
            first_char = ""
            last_char = ":"
            sign = ":"
            coma = ""
        else:
            return

        strings = f"""
        # This is an automatically generated configuration file for the CVE Binary Tool. It allows you to customize and manage the tool to suit your needs.
        # Please exercise caution when editing this file and follow the instructions provided.
        # To generate a new configuration file, use the --generate-config option. For more information, please refer to the official CVE Binary Tool documentation at https://cve-bin-tool.readthedocs.io/en/latest/.
        # This file enables you to specify options such as the installation directory of the tool, the data sources to be used, and other relevant settings. To make changes, simply modify the values to the right of the equal sign.
        # For more information on the available options and how to configure them, please refer to the official documentation at https://cve-bin-tool.readthedocs.io/en/latest/.
        # If you support the project and wish to contribute, you can find the official CVE Binary Tool Contributor Guide at https://cve-bin-tool.readthedocs.io/en/latest/CONTRIBUTING.html#cve-binary-tool-contributor-guide.
        # And link for project github https://github.com/intel/cve-bin-tool
        {first_char}cve_data_download{last_char}
          #set your nvd api key
          nvd_api_key {sign} {coma}{args["nvd_api_key"]}{coma}
          # choose method for getting CVE lists from NVD (default: api) other option available api2, json
          nvd {sign} {coma}{args["nvd"]}{coma}
          # update schedule for data sources and exploits database (default: daily)
          update {sign} {coma}{args["update"]}{coma}
        {first_char}input{last_char}
          # Directory to scan
          directory {sign} {coma}{args["directory"]}{coma}
          # To supplement triage data of previous scan or run standalone as csv2cve
          # Currently we only support csv and json file.
          input_file {sign} {coma}{args["input_file"]}{coma}
          # provide config file
          config {sign} {coma}{args["config"]}{coma}
          # specify type of software bill of materials (sbom) (default: spdx) other option are cyclonedx, swid
          sbom {sign} {coma}{args["sbom"]}{coma}
          # provide sbom filename
          sbom_file {sign} {coma}{args["sbom_file"]}{coma}
        {first_char}checker{last_char}
          # list of checkers you want to skip
          skips {sign} {coma}{args["skips"]}{coma}
          # list of checkers you want to run
          runs {sign} {coma}{args["runs"]}{coma}
        {first_char}output{last_char}
          # specify output verbosity from [debug, info, warning, error, critical]
          # verbosity will decreases as you go left to right (default: info)
          log_level {sign} {coma}{args["log_level"]}{coma}
          # if true then we don't display any output and
          # only exit-code with number of cves get returned
          # overwrites setting specified in log_level
          # Note: it's lowercase true or false
          quiet {sign} {coma}{args["quiet"]}{coma}
          # specify one of an output format: [csv, json, html, console] (default: console)
          format {sign} {coma}{args["format"]}{coma}
          # provide output filename (optional)
          # if not specified we will generate one according to output format specified
          output_file {sign} {coma}{args["output_file"]}{coma}
          # specify minimum CVE severity level to report from [low, medium, high, critical] (default: low)
          severity {sign} {coma}{args["severity"]}{coma}
          # specify minimum CVSS score to report from integer range 0 to 10 (default: 0)
          cvss {sign} {args["cvss"]}
          # Produces a report even if there are no CVE for the respective output format
          report {sign} {coma}{args["report"]}{coma}
          # Provide vulnerability exchange (vex) filename
          vex {sign} {coma}{args["vex"]}{coma}
        {first_char}other{last_char}
          # set true if you want to skip checking for newer version
          disable_version_check {sign} {coma}{args["disable_version_check"]}{coma}
          # set true if you want to autoextract archive files. (default: true)
          extract {sign} {coma}{args["extract"]}{coma}
          # operate in offline mode
          offline {sign} {coma}{args["offline"]}{coma}
        {first_char}merge_report{last_char}
          # save output as intermediate report in json format
          append {sign} {coma}{args["append"]}{coma}
          # add a unique tag to differentiate between multiple intermediate reports
          tag {sign} {coma}{args["tag"]}{coma}
          # comma separated intermediate reports path for merging
          merge {sign} {coma}{args["merge"]}{coma}
          # comma separated tag string for filtering intermediate reports
          filter {sign} {coma}{args["filter"]}{coma}
        {first_char}database{last_char}
          # export database filename
          export {sign} {coma}{args["export"]}{coma}
          # import database filename
          import {sign} {coma}{args["import"]}{coma}
        {first_char}exploit{last_char}
          # check for exploits from found cves
          exploits {sign} {coma}{args["exploits"]}{coma}
        {first_char}deprecated{last_char}
          # autoextract compressed files
          extract {sign} {coma}{args["extract"]}{coma}
      """
        f = open(f"config.{types}", "w")
        f.write(strings)
        f.close()
