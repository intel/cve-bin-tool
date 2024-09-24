# CVE Binary Tool Release Notes

## CVE Binary Tool 3.4

### Release highlights

This release comes with the finished products from our two Google Summer of Code 2024 contributors:

- GSoC 2024 contributor [@mastersans](https://github.com/mastersans) has improved our triage workflow and VEX support.
- GSoC 2024 contributor [@inosmeet](https://github.com/inosmeet) has added PURL identifier support and improved tooling for reducing false positives.

Thank you especially to [@anthonyharrison](https://github.com/anthonyharrison), [@BenL-github](https://github.com/BenL-github) and [@terriko](https://github.com/terriko) for being Google Summer of Code mentors for us this year. For more details about these projects, see the "Improved VEX support" and "PURL and mismatch database" sections below.

This release also includes

- numerous new and improved binary checkers thanks to [@ffontaine](https://github.com/ffontaine)
- improvements both to our fuzzing infrastructure and fixes for issues found (shout out to [@joydeep049](https://github.com/joydeep049) who laid a lot of groundwork here)
- many other bug fixes and features listed below.

Thanks also to the many new bug reporters who gave us feedback this release. Your feedback has been instrumental in making cve-bin-tool better, and we're so glad you've been willing to work with us as we try to find fixes for your issues. We love finding out how people use cve-bin-tool and ways we can make it more useful to you!

### Breaking changes

The `--triage--input-file` flag has been replaced by `--vex-input`. (See VEX section below for details.)

### Improved VEX support

GSoC 2024 contributor [@mastersans](https://github.com/mastersans) has improved the CVE Binary Tool by revamping the VEX workflow to integrate Lib4vex, which now handles both parsing and generating VEX files. This update aligns the sbom_manager with the vex_manager structure, enhancing overall functionality.

The focus was on integrating advanced VEX triage features, which involved a thorough refactoring of the existing workflow. This includes support for various VEX formats like CSAF, OpenVEX, and CycloneDX. Key enhancements include linking Components in the File being scanned using identifiers such as bom-ref and Package URL (purl) to precisely identify Product_Info (product, version, and vendor). Specifically, bom-ref is used in CycloneDX VEX, while purl is used in CSAF and OpenVEX formats. These identifiers help in accurately pinpointing product details like vendor and release.

The triage process has also been streamlined: the old --triage-input-file flag is replaced with the new --vex-file flag. This new flag automatically detects the VEX format and whether the file is standalone or paired with a companion file. Additionally, the --filter-triage flag allows you to filter out vulnerabilities marked as NotAffected and FalsePositive in the VEX document, ensuring that only relevant vulnerabilities are reported.

The new triaging documentation can be found here: https://cve-bin-tool.readthedocs.io/en/latest/triaging_process.html

### PURL and Mismatch database

GSoC 2024 contributor [@inosmeet](https://github.com/inosmeet) has added support for PURL identifiers and the purl2cpe database to our code, as well as a new "mismatch" database to help us fine tune product name matching.

Previously, our code assumed that the product name in a language dependency list would match the product name in our vulnerability data sources, and this sometimes produced false positives when product names were re-used across languages/vendors. Using PURLs to more precisely identify components from language scans and the purl2cpe database to look up human-verified matches in the vulnerability database should increase cve-bin-tool's accuracy.

The mismatch database provides another way to fine-tune results by allowing us to drop name collisions that are causing false positives. For example, there may be multiple languages with a package named "xml" -- if they had entries in the vulnerability databases then purl2cpe would handle finding the right one, but if they had no matches then we fallback to a search and sometimes found an incorrect set of vulnerabilities. This allows us to explicitly define mistaken matches and exclude them from results.

The new mismatch documentation can be found here: https://cve-bin-tool.readthedocs.io/en/latest/mismatch_data.html

## CVE Binary Tool 3.4rc3

Pre-release for v3.4.

## CVE Binary Tool 3.4rc2

Some late-breaking changes to improve backwards compatibility and fix a bug in comment propagation for triage.

## CVE Binary Tool 3.4rc1

Final (hopefully!) pre-release for 3.4.

## CVE Binary Tool 3.4rc0

Pre-release for v3.4

## CVE Binary Tool 3.3

### Release highlights

- GSoC 2023 contributor [@Rexbeast2](https://github.com/Rexbeast2) added support for EPSS scores to help users assess vulnerability risks (more info : https://cve-bin-tool.readthedocs.io/en/latest/MANUAL.html#metric)

- GSoC 2023 contributor [@b31ngd3v](https://github.com/b31ngd3v) has set up a github action (available here: https://github.com/intel/cve-bin-tool-action) and did a lot of work related to using our new NVD mirror (available here: https://cveb.in/)

- We now default to using our own NVD mirror unless an NVD_API_KEY is set.
  - The data is updated multiple times per day and duplicated to mirrors in several countries across the globe. They should be significantly faster than getting data from NVD directly, especially if you need to populate a database from scratch.
  - Mirroring infrastructure is provided by FCIX Software Mirrors, who currently provide a large portion of the global mirroring for linux distributions and other open source projects.
  - If you have difficulties with the mirrors or wish us to activate a mirror closer to you (we're only using a fraction of the servers available), please file an issue https://github.com/intel/cve-bin-tool/issues
  - These mirrors can be used in other tools or as part of research. We'd love to know if and how you use them!

- Breaking Change: Windows users will now need to use python 3.12 if they want to scan tarfiles.
  - Testing has been disabled on windows for python < 3.12. It's likely that older versions of python will continue to work on Windows as long as you don't need tarfile support, but our binary checker tests use tarfiles so we can no longer run the full test suite.

- We now provide our own version compare function, which will not be limited to PEP 440 compliant semantic versions.

- Thanks especially to [@ffontaine](https://github.com/ffontaine) we are up to 359 binary checkers!

- Our fuzz testing has been improved to cover more of our language file parsers. Thanks especially to [@joydeep049](https://github.com/joydeep049), [@mastersans](https://github.com/mastersans), [@raffifu](https://github.com/raffifu) and [@inosmeet](https://github.com/inosmeet) for their work in setting these up and fixing errors found via fuzzing.

We've also got a large number of new contributors, many of whom participated in Hacktoberfest 2023 or the first part of GSoC 2024, as well as users and security experts who were generous enough to share their time and expertise with us outside of these open source beginner-focused programs. Thank you!

## CVE Binary Tool 3.3rc3 pre-release

Assorted bugfixes, new checkers, and improvements (see details below). This may be the last pre-release before 3.3 if we don't find any additional issues.

BREAKING CHANGE: Windows users will now have to use python 3.12 if they intend to scan tarfiles.

## CVE Binary Tool 3.3rc2 pre-release

This pre-release improved the version compare function so it can handle certain distro versions and other special version cases more smoothly. Note that it does not have any special handling for hashes because they appear infrequently in the NVD data, but you may have some unpredictable results if you have hashes listed in an SBOM or local version.

## CVE Binary Tool 3.3rc1 pre-release

This has some fixes for the version compare function that were reported against the previous pre-release, as well as some new checkers and bugfixes.

## CVE Binary Tool pre-release 3.3a0

Preview release for 3.3, which will hopefully be coming in December.

There's a *lot* of changes in this release, but I'm particularly eager to have people try out the new version compare function and make sure it is sufficiently robust for arbitrary versions, as we needed to migrate away from the function provided in python packaging as it could not handle some of the versions we see in the NVD data.

## CVE Binary Tool 3.2.1

Due to a change in the data used for the `curl` data source, we're issuing a slightly out of band point release for users unable to use 3.2.

There are a number of checker updates to address false positives, new checkers, and other bug fixes and features as described below.

One commonly requested feature has made it into this release: generation of SBOMs. Please try it out and let us know where it can be improved!

Thanks especially to the *many* new contributors in this release

- Many of you joined us via the Google Summer of Code 2023 selection process: I wish we'd had mentors and slots available to have more of you as paid contributors this year!
- Some of you also joined us via the Intel Open Source Hackathon: thank you so much for taking the time to work with us and it's been a delight to work with so many experienced coders during the event.
- And some of you just stopped by on your own with great ideas and fixes. Thank you!


## CVE Bin Tool pre-release 3.2.1rc0

Due to a change in the data used for the `curl` data source, we're issuing a slightly out of band point release for users unable to use 3.2.

There are a number of checker updates to address false positives, new checkers, and other bug fixes and features.

One commonly requested feature has made it into this release: generation of SBOMs. Please try it out and let us know where it can be improved!

## CVE Binary Tool 3.2

### New features from our GSoC 2022 participants:

* **@yashugarg** added a large number of tests and work on fuzzing our interfaces
* **@rhythmrx9** added new data sources (we now support advisories from Gitlab, OSV and Redhat as well as NVD)
* **@XDRAGON2002** for the new parsers that allow us to scan things like Ruby Gemfiles, Rust cargo files, and more.

### Other interesting features in this release:

* **@ffontaine** has added a large number of new checkers, pushing us well over 200 binary checkers.
* **@anthonyharrison** has added initial support for NVD API 2.0. Note that at the time this was added the 2.0 version didn't work with their API keys, so the code behaves accordingly.

Thanks also to @BreadGenie for code review and mentoring support as well as a number of contributions listed below. A special shout out to @b31ngd3v and @metabiswadeep whose first contributions are in this release but they've been the first of many, as well as the many other folk who got their first commits in via Hacktoberfest or GSoC or goodfirstissue.dev or however you found us. Thanks to everyone for being part of this release!

## CVE Bin Tool pre-release 3.2rc0

Preview release for 3.2.

We're currently seeing an issue in our testing system where Windows systems are taking a long time to upgrade the database to store additional data source information. Windows users are particularly encouraged to try this pre-release to see if you have any issues!

When updating your database, make sure your [NVD_API_KEY is set](https://nvd.nist.gov/developers/request-an-api-key) and you may have better results using ```-u now``` to get a fresh database.

## CVE Binary Tool 3.1.2

Minor update to force a downgrade of packaging to allow use of LegacyVersion (fixes [#2428](https://github.com/intel/cve-bin-tool/issues/2428))

This is intended to be a temporary fix while we finish up the 3.2 release, but I believe we will be able to backport the removal for LegacyVersion without much trouble, so there may be one more release for the 3.1 tree if it looks like 3.2 is going to take more than a week.

**Full Changelog**: [```v3.1.1...v3.1.2```](https://github.com/intel/cve-bin-tool/compare/v3.1.1...v3.1.2)

## CVE Binary Tool 3.1.1

Minor typo necessitated a version bump + new release.


## CVE Binary Tool 3.1

This release is dedicated to the person who sent me cookies after I was griping about differences in Python 3.7 error handling on Twitter. They were delicious, thank you! Thanks also to the many new contributors who have joined us as part of Google Summer of Code 2022. You can see many new folk had their first commits in this release!

### New Features

* CVE Binary Tool 3.1 adds support for [NVD API keys.](https://nvd.nist.gov/general/news/API-Key-Announcement) An NVD API key allows registered users to make a greater number of requests to the API. At this time, the [NVD API documentation says](https://nvd.nist.gov/developers), "The public rate limit (without an API key) is 10 requests in a rolling 60 second window; the rate limit with an API key is 100 requests in a rolling 60 second window."
   * cve-bin-tool updates once per day by default to limit connections to NVD, but users in shared environments or running more frequent updates have occasionally seen 403 errors due to exceeded rate limits. Using an API key should alleviate those issues going forwards.
* New support for scanning Java and JavaScript packages has been added. (Yes, this will now detect log4j packages.) The language-specific packages we support now are Java, JavaScript and Python.
* A new offline flag (```--offline```) has been added to disable all network requests for use in isolated environments. [A guide for using --offline mode can be found here.](https://cve-bin-tool.readthedocs.io/en/latest/how_to_guides/offline.html)
* New support [VEX (Vulnerabity Exploitablity Exchange)](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf) files. Files could be generated following a scan and then used as a supported triage file.
* Extractor support has been extended to include WAR, EAR, pkg and zst files.
* New checkers: Libsrtp, libseccomp, libebml, libsolv

### Changed Features

* Some users had expressed concern that they would prefer not to install the Reportlab dependency on their systems due to security concerns if the library is mis-used, so we no longer install it by default.
  * Users intending to use PDF export can use ```pip install cve-bin-tool[PDF]``` to add reportlab to their install. or ```pip install reportlab``` if they decide they want it later.
  * Similarly, users can ```pip uninstall reportlab``` at any time and cve-bin-tool will continue to function although without the ability to export PDF files. Users can generate their own using pdf reports using print-to-pdf on an HTML report if needed.
* Python 3.6 support and testing has been dropped as Python 3.6 has reached end of life. (This may affect some users on CentOS.)

## CVE Binary Tool 3.1rc3
Full Changelog: v3.1rc2...v3.1rc3


## CVE Binary Tool 3.1rc2
Potentially the final release candidate for CVE Binary Tool 3.1. (Note the change in naming scheme to match the pip upload)


## CVE Binary Tool 3.1.pre1

Second pre-release. This one has all features expected for release and will undergo some additional validation before final release.


## CVE Binary Tool 3.1.pre0

Pre-release for what will eventually be 3.1. There are a few PRs still in progress, and you can see what remains to be updated in the [3.1 milestone](https://github.com/intel/cve-bin-tool/milestone/7). The release notes below are auto-generated by GitHub.


## CVE Binary Tool 3.0

The CVE Binary Tool 3.0 release includes improved tools for checking known lists of packages including Linux distributions, improved methods of communication with NVD to get vulnerability data, additional checkers, and significant refactoring to streamline the output.

### New feature highlights:
* **SBOM Scanning**: CVE Binary Tool can now take Software Bill of Materials (SBOM) files to help users improve their supply chain security data for all known dependencies. The initial feature can handle some versions of SPDX, CycloneDX and SWID formats. More information on SBOM scanning can be found here: https://github.com/intel/cve-bin-tool/blob/main/doc/how_to_guides/sbom.md
* **Known vulnerability information**: Users scanning some linux distro packages can now get additional information about fixes available for those platforms.
* **Vulnerability Data**: The default method for getting NVD vulnerability lists has been changed.  Previously we downloaded full yearly JSON files if anything in the year had changed, the new API allows us to get only the latest changes. Users may see a speedup during the update phase as a result.
* **(Breaking change) Return codes:** The return codes used by CVE Binary Tool have changed.  
   * A 0 will be returned if no CVEs are found, a 1 will be returned if any CVEs were found (no matter how many), and codes 2+ indicate operational errors.  A full list of error codes is available here: https://github.com/intel/cve-bin-tool/blob/main/cve_bin_tool/error_handler.py 
   * Previously we returned the number of CVEs found, but this could exceed the expected range for return codes and cause unexpected behaviour.

Thanks especially to our 2021 GSoC students, @BreadGenie, @imsahil007 and @peb-peb whose final GSoC contributions are part of this release.

A full list of changes is available in GitHub. https://github.com/intel/cve-bin-tool/releases/tag/v3.0 

Commit messages use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format.


## CVE Binary Tool 2.2.1

Release date: 04 Aug 2021

The 2.2.1 release relaxes the behaviour when file extraction fails, which was causing problems for some users scanning files with .exe and .apk file extensions using the previous release. In 2.2 all extraction fails caused the tool to halt and throw an exception, in 2.2.1 the tool will log a warning and continue.

## CVE Binary Tool 2.2 

Release date: 08 Jul 2021

The 2.2 release contains a number of bugfixes and improvements thanks to the many students who contributed as part of our Google Summer of Code selection process.  Congratulations to @BreadGenie, @imsahil007 and @peb-peb who will be continuing to work with us for the next few months!  

New feature highlights:
- CVE Binary Tool can now be used to get lists of vulnerabilities affecting a python requirements.txt file, as well as lists of packages installed on .deb or .rpm based systems (Thanks to @BreadGenie)
- Scan reports can now be merged (Thanks to @imsahil007)
- Reports can now be generated in PDF format (Thanks to @anthonyharrison)
- A new helper script is available to help new contributors find appropriate patterns for new checkers (Thanks to @peb-peb)
- Reports can now be generated even if no CVEs are found (Thanks to @BreadGenie) 
- We've added rate limiting for our NVD requests (Thanks to @nisamson, @param211,  @bhargavh)

There are also a number of new checkers and bug fixes.

Thanks also to @jerinjtitus, @Molkree, @alt-glitch, @CabTheProgrammer, @Romi-776, @chaitanyamogal, @Rahul2044, @utkarsh147-del , @SinghHrmn, @SaurabhK122, @pdxjohnny and @terriko for their contributions to this release.

## CVE Binary Tool 2.1.post1

Release date: 27 Apr 2021

Rate limiting temporary fix in response to NVD API update

## CVE Binary Tool 2.1

Release date: 07 Dec 2020

This release fixes an issue with jinja2 autoescape breaking the HTML reports
and includes some updates to tests.

## CVE Binary Tool 2.0

Release date: 12 Nov 2020

This release features code from our three successful Google Summer of Code students!

* @SinghHrmn made improvements to our output formats, including adding a
  new HTML human-readable report format.  You can try out a demo at <https://intel.github.io/cve-bin-tool/>
  * Read [Harmandeep's final GSoC report](https://gist.github.com/SinghHrmn/dd83b31b22bf73e45bd8489117e20a96) for more details.

* @Niraj-Kamdar improved the performance of cve-bin-tool and its tests,
 provided significant code modernization and added input modes so you can now
add and re-use triage data with your scans.  
  * Read [Niraj's final GSoC report](https://dev.to/nirajkamdar/cve-binary-tool-gsoc-final-report-4nlk) for more details

* @SaurabhK122 added a huge number of new checkers to the tool, both in this release and the previous one.
  * Read [Saurabh's final GSoC report](https://gist.github.com/SaurabhK122/a32947749fde10cfea80bdbd1f388da6) for more details

Thanks also to the mentors who worked with our students this year: @terriko, @pdxjohnny, @meflin, @mdwood-intel and unofficial mentor @anthonyharrison who helped us considerably with real-world feedback.

This release also includes contributions from the following new contributors:

* @anthonyharrison
* @imsahil007
* @chaitanyamogal
* @Rahul2044
* @Wicked7000
* @willmcgugan
* @kritirikhi
* @sakshatshinde

## CVE Binary Tool 1.1.1

Release Date: 9 Nov 2020

This point release includes fixes so documentation will build and display correctly on readthedocs. There are no functional changes to the code.

## CVE Binary Tool 2.0 alpha release

Release Date: 29 Oct 2020

This is an alpha release for people interested in trying out an early preview of 2.0. Major features include performance improvements, triage options, new output modes, and many new checkers thanks to our Google Summer of Code students @Niraj-Kamdar, @SinghHrmn and @SaurabhK122 . Thanks for an incredibly productive summer!

We are expecting to make some documentation improvements before the final release, which we hope to have out next week.

## CVE Binary Tool 1.1

Release Date: 29 Oct 2020

This is an alpha release for people interested in trying out an early preview of 2.0. Major features include performance improvements, triage options, new output modes, and many new checkers thanks to our Google Summer of Code students @Niraj-Kamdar, @SinghHrmn and @SaurabhK122 . Thanks for an incredibly productive summer!

We are expecting to make some documentation improvements before the final release, which we hope to have out next week.

## CVE Binary Tool 1.0

Release Date: 20 Apr 2020

This release includes major improvements to the way NVD data is used and
stored.  **If you have tried the development tree from GitHub, you may wish
to run `cve-bin-tool -u now` after you upgrade to remove old data.**

There are now three output formats:

* Console (like before only prettier)
* CSV (comma-delimited text, suitable for import into spreadsheets)
* JSON (suitable for machine parsing)

And 17 new checkers (as well as improved tests for some of the old):

* binutils
* bluez
* bzip2
* ffmpeg
* gnutls
* gstreamer
* hostapd
* libcurl
* libdb
* ncurses
* nginx
* openssh
* python
* rsyslog
* strongswan
* syslogng
* varnish

Thanks to our many new and returning contributors for this 1.0 release.  We have 21 new contributors since I last thanked people in 0.3.0:

* @abhaykatheria
* @ableabhinav
* @AkechiShiro
* @ananthan-123
* @bigbird555
* @brainwane
* @FReeshabh
* @hur
* @k-udupa2000
* @mariuszskon
* @Niraj-Kamdar
* @nitishsaini706
* @oh6hay
* @param211
* @Purvanshsingh
* @SaurabhK122
* @sbs2001
* @shreyamalviya
* @SinghHrmn
* @svnv
* @utkarsh261

And I'd like to make a quick list of our previous contributors, some of whom have continued to be active for this release:

* @bksahu
* @CaptainDaVinci
* @GiridharPrasath
* @pdxjohnny
* @PrajwalM2212
* @rossburton
* @sanketsaurav
* @sannanansari
* @terriko
* @wzao1515

Thanks also to the many people who reported bugs and helped us make things
better!  

I want to particularly thank all those involved with Google Summer
of Code -- not only have you made our code better, but you've also helped us
improve our onboarding process and just brought a huge amount of energy to
this project in 2020.  

## CVE Binary Tool 0.3.1

Release Date: 27 Nov 2019

This release contains fixes so the CVE Binary Tool handles the new CVSS 3.1 data correctly.  

You may also notice some new checkers thanks to our Hacktoberfest participants!  We're still working on more robust tests before they're fully supported, but we figured it was more fun to give you the preview than specifically withhold them.  Have fun, and please file bugs if anything doesn't work for you so we know how to best to target our testing.

## CVE Binary Tool 0.3.0

Release date: 13 Aug 2019

The 0.3.0 release adds Windows support to the cve-bin-tool, with many thanks to @wzao1515 who has been doing amazing work as our Google Summer of Code Student!  

New checkers in this release:

* icu
* kerberos
* libgcrypt
* libjpeg
* sqlite
* systemd

New flags:

* -s / --skip
  * allows you to disable a list of checkers
* -m / --multithread
  * lets the scanner run in multithreaded mode for improved performance
* -u / --update
  * allows you to choose if the CVE information is updated.  Default is daily.

This release also contains a number of bugfixes and improved signatures.  

Many thanks to our new contributors in this release:
@wzao1515 @PrajwalM2212 @rossburton @GiridharPrasath @sannanansari @sanketsaurav @bksahu @CaptainDaVinci
As well as the many people who reported bugs and helped us make things better!

## CVE Binary Tool 0.2.0

Initial release, 18 Jan 2019.
