# Scanning installed packages

`-L` or `--package-list` option runs a CVE scan on installed packages listed in a package list. It takes a python package list (requirements.txt) or a package list of packages of systems that has dpkg, pacman or rpm package manager as an input for the scan. This option is much faster and detects more CVEs than the default method of scanning binaries.

You can get a package list of all installed packages in

- a system using dpkg package manager by running `dpkg-query -W -f '${binary:Package}\n' > pkg-list.txt`
- a system using pacman package manager by running `pacman -Qqe > pkg-list.txt`
- a system using rpm package manager by running `rpm -qa --queryformat '%{NAME}\n' > pkg-list.txt`

in the terminal and provide it as an input by running `cve-bin-tool -L pkg-list.txt` for a full package scan.