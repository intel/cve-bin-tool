import json
import os

import requests

license_dir, filename = os.path.split(__file__)
# Bodge the pathname
license_path = os.path.join(
    license_dir, "../lib4sbom/license_data", "spdx_licenses.json"
)
licfile = open(license_path, "r", encoding="utf-8")
licenses = json.load(licfile)

# Process each licence
for lic in licenses["licenses"]:
    # print (lic)
    id = lic["licenseId"].lower()
    name = lic["name"].lower()
    url = lic["detailsUrl"]
    print(f"{name} - {id}: {url}")

    filename = f"{id}.txt"
    file_path = os.path.join(license_dir, "../lib4sbom/license_data/text", filename)
    # Get text
    try:
        license_text = requests.get(url).json()
        if license_text.get("licenseText") is not None:
            # text=license_text["licenseText"]
            html = license_text["licenseTextHtml"]
            # print (html)
            # Create file
            with open(file_path, "w") as f:
                f.write(html)
    except requests.exceptions.RequestException:
        print(f"Unable to find license text for {name}")
