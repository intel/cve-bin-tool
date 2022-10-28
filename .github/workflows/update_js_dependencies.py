import json
import shutil
import urllib.request
import zipfile
from pathlib import Path

# bootstrap
_json = json.loads(
    urllib.request.urlopen(  # nosec: redirects to the latest GH release
        urllib.request.Request(
            "https://api.github.com/repos/twbs/bootstrap/releases/latest",
            headers={"Accept": "application/vnd.github.v3+json"},
        )
    ).read()
)
asset = next(x for x in _json["assets"] if "dist" in x["name"])
asset_name: str = asset["name"]
urllib.request.urlretrieve(  # nosec: link is within GH
    asset["browser_download_url"], asset_name
)

with zipfile.ZipFile(asset_name, "r") as zip_ref:
    zip_ref.extractall()

tmp_dir = Path(asset_name).stem
shutil.copy(
    Path(tmp_dir, "js", "bootstrap.min.js"),
    Path("cve_bin_tool", "output_engine", "html_reports", "js", "bootstrap.js"),
)

shutil.rmtree(tmp_dir)
Path(asset_name).unlink()

# plotly.js
_json = json.loads(
    urllib.request.urlopen(  # nosec: redirects to the latest GH release
        urllib.request.Request(
            "https://api.github.com/repos/plotly/plotly.js/releases/latest",
            headers={"Accept": "application/vnd.github.v3+json"},
        )
    ).read()
)
urllib.request.urlretrieve(  # nosec: tag name comes from plotly maintainers
    f"https://github.com/plotly/plotly.js/raw/{_json['tag_name']}/dist/plotly.min.js",
    Path("cve_bin_tool", "output_engine", "html_reports", "js", "plotly.js"),
)
