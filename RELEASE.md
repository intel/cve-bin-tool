# CVE Binary Tool Release Notes

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
