import csv
import json
import os
import sys
import pygal
import webbrowser

from datetime import datetime
from jinja2 import Environment, FileSystemLoader

from .log import LOGGER


class OutputEngine(object):
    # Max space for each console tabular cell
    MODULENAME_MAX = 18
    VERSION_MAX = 9
    CVE_NUMBER_MAX = 18
    CVE_SEVERITY_MAX = 9
    DOTS = "..."

    def __init__(self, filename=None, modules=None, logger=None):
        if logger is None:
            logger = LOGGER.getChild(self.__class__.__name__)
        self.filename = filename
        self.modules = modules
        self.logger = logger
        self.formatted_output = self.format_output()

    def generate_filename(self, extension=None):
        """ Generates a random filename"""
        if extension:
            now = datetime.now().strftime("%Y-%m-%d.%H-%m-%S")
            self.filename = f"output.cve-bin-tool.{now}.{extension}"

    def output_cves(self, outfile, output_type=None):
        """ Output a list of CVEs
        format self.modules[checker_name][version] = dict{id: severity}
        to other formats like CSV or JSON
        """
        if output_type == "json":
            self.output_json(outfile)
        elif output_type == "csv":
            self.output_csv(outfile)
        # elif output_type == "html":  # for now just generate dummy data
        #    self.output_html()
        else:  # console, or anything else that is unrecognised
            self.output_console(outfile)

    def format_output(self):
        """
        summary: format output in the list of dictionary format.
        
        Returns:
            type: list(dict) -- example: [{ "package": "curl",
                                            "version": "1.2.1",
                                            "cve_number": "CVE-1234-1234", 
                                            "severity": "LOW"},
                                            ...]
        """
        formatted_output = []
        for package in self.modules:
            for version, cves in self.modules[package].items():
                for cve_number, cve_severity in cves.items():
                    formatted_output.append(
                        {
                            "package": package,
                            "version": version,
                            "cve_number": cve_number,
                            "severity": cve_severity,
                        }
                    )
        return formatted_output

    def output_json(self, outfile):
        """ Output a JSON of CVEs """
        json.dump(self.formatted_output, outfile, indent="    ")

    def output_csv(self, outfile):
        """ Output a CSV of CVEs """
        writer = csv.DictWriter(
            outfile, fieldnames=["package", "version", "cve_number", "severity"]
        )
        writer.writeheader()
        writer.writerows(self.formatted_output)

    def write_console(self, modulename, version, cve_number, cve_severity, outfile):
        """ Output Module, Version, CVE_Number, Severity to the console in tabular form"""

        if len(modulename) > (self.MODULENAME_MAX - len(self.DOTS)):
            modulename = modulename[: self.MODULENAME_MAX - len(self.DOTS)] + self.DOTS

        # Calculate length of -- modulename, version, cve_number, cve_severity
        modulename_len = len(modulename)
        version_len = len(str(version))
        cve_number_len = len(cve_number)
        cve_severity_len = len(cve_severity)

        # Generate all the fields with appropriate space to be fit into tabular form
        modulename = f"{modulename}{' ' * (self.MODULENAME_MAX - modulename_len)}"
        version = f"{version}{' ' * (self.VERSION_MAX - version_len)}"
        cve_number = f"{cve_number}{' ' * (self.CVE_NUMBER_MAX - cve_number_len)}"
        cve_severity = (
            f"{cve_severity}{' ' * (self.CVE_SEVERITY_MAX - cve_severity_len)}"
        )

        # End string marks end for the previous length data
        end_string = f"+{'-' * (self.MODULENAME_MAX + 2)}+{'-' * (self.VERSION_MAX + 2)}+{'-' * (self.CVE_NUMBER_MAX + 2)}+{'-' * (self.CVE_SEVERITY_MAX + 2)}+\n"

        # string generate the details in tabular form
        string = f"| {modulename} | {version} | {cve_number} | {cve_severity} |\n"

        # Write String and End String to the console
        outfile.write(string)
        outfile.write(end_string)

    def output_console(self, outfile):
        """ Output list of CVEs in a tabular format  """

        # Now contains the time at which report is generated
        now = datetime.now().strftime("%Y-%m-%d  %H:%m:%S")

        # The main heading containing CVE-Bin-Tool logo
        heading = f"""
+=================================================================+
|   ___ _    __ ____    ___  ___  _   _    _____  ___  ___  _     |                         
|  / __| \  / /| ___]  |   )[   ]| \ | |  [_   _]| _ || _ || |    |                                   
| | |__ \ \/ / | _]_ = | <   | | | |\| | =  | |  ||_||||_||| |__  |                               
|  \___| \__/  |___ ]  |___)[___]|_| \_|    |_|  |___||___||____| |
|                                                                 |
+=================================================================+
|   CVE Binary Tool Report Generated: {now}        |
+=================================================================+

+=================================================================+
|   MODULE NAME      |  VERSION  |    CVE NUMBER      | SEVERITY  |
+=================================================================+
"""

        # Outputs Heading to the console
        outfile.write(heading)

        # for every module that is scanned -- output to the console
        for output in self.formatted_output:
            # call to the write_console function for each module,version
            self.write_console(
                output["package"],
                output["version"],
                output["cve_number"],
                output["severity"],
                outfile,
            )

    def output_file(self, output_type="csv"):

        """ Generate a file for list of CVE """
        if self.filename == sys.stdout:
            # short circuit file opening logic if we are actually
            # just writing to stdout
            self.output_cves(self.filename, output_type)
            return

        # Check if we need to generate a filename
        if self.filename is None:
            self.generate_filename(output_type)
        else:
            # check if the filename already exists
            file_list = os.listdir(os.getcwd())
            if self.filename in file_list:
                self.logger.warning(
                    f"Failed to write at '{self.filename}'. File already exists"
                )
                self.logger.info(
                    "Generating a new filename with Default Naming Convention"
                )
                self.generate_filename(output_type)

            # try opening that file
            try:
                with open(self.filename, "w") as f:
                    f.write("testing")
                os.remove(self.filename)
            except Exception as E:
                self.logger.warning(E)
                self.logger.info("Switching Back to Default Naming Convention")
                self.generate_filename(output_type)

        # Log the filename generated
        self.logger.info(f"Output stored at {os.getcwd()}/{self.filename}")

        # call to output_cves
        with open(self.filename, "w") as f:
            self.output_cves(f, output_type)

    def output_html(self):
        """Returns a HTML report for CVE's
        """
        # Example Code ---  this will only generate dummy data

        root = os.path.dirname(os.path.abspath(__file__))
        templates_dir = os.path.join(root, "html/templates")
        env = Environment(loader=FileSystemLoader(templates_dir))
        template = env.get_template("base.html")

        # configration file
        config = pygal.Config()
        config.disable_xml_declaration = True
        config.legend_at_bottom = True
        config.legend_at_bottom_columns = 5
        config.human_readable = True

        cve_bar = pygal.Bar(config, title="Product CVEs")
        cve_bar.add("Python 3.6.9", 4)
        cve_bar.add("Python 3.7.1", 3)
        cve_bar.add("Python 3.8.0", 6)
        cve_bar.add("curl 1.2", 2)
        cve_bar.add("curl 1.3", 8)
        cve_bar.add("curl 1.4", 5)
        cve_bar.add("curl 1.5", 2)
        cve_bar.add("libxml 2.6.7", 1)

        product_pie = pygal.Pie(config, inner_radius=0.4, show_legend=False, margin=-10)
        product_pie.add("Vulnarable", [{"value": 7, "color": "red"}])
        product_pie.add("No Known Vulnarability", [{"value": 12, "color": "green"}])

        python_pie = pygal.Pie(
            config, inner_radius=0.4, show_legend=True, title="Severity Analysis"
        )
        python_pie.add("CRITICAL", [{"value": 5, "color": "red"}])
        python_pie.add("HIGH", [{"value": 2, "color": "orange"}])
        python_pie.add("MEDIUM", [{"value": 1, "color": "yellow"}])
        python_pie.add("LOW", [{"value": 3, "color": "green"}])

        filename = os.path.join(root, "html/Example", "example.html")
        with open(filename, "w") as fh:
            fh.write(
                template.render(
                    date=datetime.datetime.now().strftime("%d %b %Y"),
                    graph_cves=cve_bar.render(),
                    graph_products=product_pie.render(),
                    severity=python_pie.render(),
                )
            )

        webbrowser.open_new_tab("html/Example/example.html")
