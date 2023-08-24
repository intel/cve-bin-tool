# How do I run CVE Binary Tool in GitHub Actions?

CVE Binary Tool can be run in GitHub Actions in order to scan your project dependencies for any CVEs. To understand what GitHub Actions are and how they work, you can refer to the [official documentation](https://docs.github.com/en/actions/learn-github-actions/understanding-github-actions).

Workflows in GitHub Actions are defined in YAML files in your code repository in the [`.github/workflows`](https://github.com/intel/cve-bin-tool/tree/main/.github/workflows) directory. These workflows are triggered whenever some events are set off in the repository, for example, whenever a Pull Request is made.

## Adding the workflow to your repository

To add the tool to your workflow, place the [`cve_scanner_gh_action.yml`](https://github.com/intel/cve-bin-tool/blob/main/doc/how_to_guides/cve_scanner_gh_action.yml) file, or copy it from below into the `.github/workflow` directory of your repository and you should be good to go!

`cve_scanner_gh_action.yml`:

```yml
name: CVE scanner
on:
  # You can customize this according to your need.
  - push
  - pull_request
jobs:
  build_and_scan:
    runs-on: ubuntu-22.04
    steps:
      # Get date utility for caching database.
      - name: Get Date
        id: get-date
        run: |
          echo "date=$(/bin/date -u "+%Y%m%d")" >> $GITHUB_OUTPUT
        shell: bash
      # Let's first download dependencies for this action.
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'
      # This second step is unnecessary but highly recommended because
      # It will cache database and saves time re-downloading it if database isn't stale.
      - name: get cached python packages
        uses: actions/cache@v3
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-
      - name: get cached database
        uses: actions/cache@v3
        with:
          path: cache
          key: Linux-cve-bin-tool-${{ steps.get-date.outputs.date }}
      - name: Install CVE Binary Tool
        # We are using latest development version of CVE Binary Tool
        # because current PyPI version don't have features like config file support,
        # generating HTML report etc.
        run: |
          [[ -e cache ]] && mkdir -p .cache && mv cache ~/.cache/cve-bin-tool
          pip install git+https://github.com/intel/cve-bin-tool@main
      # In case you prefer current PyPI version, you need to hard code CLI options
      # for cve-bin-tool in the action itself and have to use CSV or JSON as output format.
      # pip install cve-bin-tool
      - name: build package
        # Here, we are building Python wheel for this example.
        # You need to replace this with your build process.
        run: |
          pip install wheel
          python setup.py bdist_wheel
      - name: Scan built package
        # Here, we are scanning built wheel which is situated in /dist directory
        # Python stores built packages in /dist directory.
        # You need to replace it with the directory where you have stored built package
        run: cve-bin-tool dist -f html -o cve-bin-tool-report.html -x
        #  Alternatively if you have written config file for cve-bin-tool you can use following command
        #  cve-bin-tool -C path/to/cve_bin_tool_config.toml
        continue-on-error: true
      # You need to set continue_on_error: true because CVE Binary Tool sets number of cves
      # as exit code. And GitHub terminates action when process produces
      # nonzero exit code status.
      - name: Upload report as an artifact
        # This will upload generated report as an GitHub artifact which you can download later.
        uses: actions/upload-artifact@v2
        with:
          name: cve_report
          path: 'cve-bin-tool-report.html'
```

## Summary of the workflow

The workflow file itself is pretty well-commented and explained. It should be easy to understand what it does by reading through it.

1. On every push or pull request, the workflow is triggered (this is considered an event). On an Ubuntu virtual environment, CVE Binary Tool is set up and installed.

2. After this, a Python Wheel is built for your project's requirements and dependencies. If your build process is different, then you should replace this step with your build process.

3. The tool then scans the built wheel situated in the `/dist` directory. Again, if your build process is different, you are going to need to change this step too.

4. Now the workflow will upload the generated HTML report as GitHub artifact to refer to later.
