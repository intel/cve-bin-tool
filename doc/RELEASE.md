# CVE Binary Tool Release Notes

## CVE Binary Tool 2.1

Release Date: 07 Dec 2020

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
stored.  **If you have tried the development tree from Github, you may wish
to run `cve-bin-tool -u now` after you upgrade to remove old data.**

There are now three output formats:

* Console (like before only prettier)
* CSV (comma-delimted text, suitable for import into spreadsheets)
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
* ngnix
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

You may also notice some new checkers thanks to our Hacktoberfest participants!  We're still working on more robust tests before they're fully supported, but we figured it was more fun to give you the preview than specifically withold them.  Have fun, and please file bugs if anything doesn't work for you so we know how to best to target our testing.

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
