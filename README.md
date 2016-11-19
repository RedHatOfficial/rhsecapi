# rhsecapi

`rhsecapi` makes it easy to interface with the [Red Hat Security Data API](https://access.redhat.com/documentation/en/red-hat-security-data-api/) -- even from [behind a proxy](https://github.com/ryran/rhsecapi/issues/29). From the rpm description:

> **Leverage Red Hat's Security Data API to find CVEs by various attributes (date, severity, scores, package, IAVA, etc). Retrieve customizable details about found CVEs or about specific CVE ids input on cmdline. Parse arbitrary stdin for CVE ids and generate a customized report, optionally sending it straight to pastebin. Searches are done via a single instantaneous http request and CVE retrieval is parallelized, utilizing multiple threads at once. Python requests is used for all remote communication, so proxy support is baked right in. BASH intelligent tab-completion is supported via optional Python argcomplete module. Python2 tested on RHEL6, RHEL7, & Fedora but since it doesn't integrate with RHN/RHSM/yum/Satellite, it can be used on any internet-connected machine. Feedback, feature requests, and code contributions welcome.**

If you don't have a GitHub account but do have a Red Hat Portal login, go here: [New cmdline tool using Red Hat's new Security Data API: rhsecapi](https://access.redhat.com/discussions/2713931).

## Jump to ...
- [Simple CVE retrieval](#simple-cve-retrieval)
- [Installation](#installation)
- [Abbreviated usage](#abbreviated-usage)
- [BASH intelligent tab-completion](#bash-intelligent-tab-completion)
- [Field display](#field-display)
- [Find CVEs](#find-cves)
  - [Empty search: list CVEs by public-date](#empty-search-list-cves-by-public-date)
  - [Find CVEs by attributes](#find-cves-by-attributes)
  - [Find CVEs by IAVA](#find-cves-by-iava)
- [Advanced: find unresolved CVEs for a specific package in a specific product](#advanced-find-unresolved-cves-for-a-specific-package-in-a-specific-product)
- [Full help page](#full-help-page)
- [Working with backend rhsda library](#working-with-backend-rhsda-library)

## Simple CVE retrieval

Specify as many CVEs on cmdline as needed; certain details are printed to stderr -- e.g., in the following, the first 4 lines of output were sent to stderr

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 3 of 4
[NOTICE ] rhsda: Invalid CVE queries: 1 of 4

CVE-2013-4113
  SEVERITY: Critical Impact
  DATE:     2013-07-11
  BUGZILLA: 983689
  FIXED_RELEASES:
   Red Hat Enterprise Linux 5 [php-5.1.6-40.el5_9]: RHSA-2013:1049
   Red Hat Enterprise Linux 5 [php53-5.3.3-13.el5_9.1]: RHSA-2013:1050
   Red Hat Enterprise Linux 6 [php-5.3.3-23.el6_4]: RHSA-2013:1049
   Red Hat Enterprise Linux Extended Lifecycle Support 3 [php-4.3.2-56.ent]: RHSA-2013:1063
   Red Hat Enterprise Linux Extended Lifecycle Support 4 [php-4.3.9-3.37.el4]: RHSA-2013:1063
   Red Hat Enterprise Linux EUS (v. 5.6 server) [php-5.1.6-27.el5_6.5]: RHSA-2013:1061
   Red Hat Enterprise Linux EUS (v. 5.6 server) [php53-5.3.3-1.el5_6.3]: RHSA-2013:1062
   Red Hat Enterprise Linux Extended Update Support 6.2 [php-5.3.3-3.el6_2.10]: RHSA-2013:1061
   Red Hat Enterprise Linux Extended Update Support 6.3 [php-5.3.3-14.el6_3.1]: RHSA-2013:1061
   Red Hat Enterprise Linux Long Life (v. 5.3 server) [php-5.1.6-23.4.el5_3]: RHSA-2013:1061
  FIX_STATES:
   Not affected: Red Hat Enterprise Linux 7 [php]

CVE-2014-3669
  SEVERITY: Moderate Impact
  DATE:     2014-09-18
  BUGZILLA: 1154500
  FIXED_RELEASES:
   Red Hat Enterprise Linux 5 [php53-5.3.3-26.el5_11]: RHSA-2014:1768
   Red Hat Enterprise Linux 5 [php-5.1.6-45.el5_11]: RHSA-2014:1824
   Red Hat Enterprise Linux 6 [php-5.3.3-40.el6_6]: RHSA-2014:1767
   Red Hat Enterprise Linux 7 [php-5.4.16-23.el7_0.3]: RHSA-2014:1767
   Red Hat Enterprise Linux Extended Update Support 6.5 [php-5.3.3-27.el6_5.3]: RHSA-2015:0021
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 6) [php54-php-5.4.16-22.el6]: RHSA-2014:1765
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 6) [php55-php-5.5.6-13.el6]: RHSA-2014:1766
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 7) [php54-php-5.4.16-22.el7]: RHSA-2014:1765
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 7) [php55-php-5.5.6-13.el7]: RHSA-2014:1766

CVE-2004-0230
  BUGZILLA: No Bugzilla data
   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy

CVE-2015-4642
  Not present in Red Hat CVE database
  Try https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4642
```

A `--product` option allows spotlighting a particular product via a case-insenstive regex, e.g., here's the same exact command above spotlighting EUS products:

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642 --product eus
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 3 of 4
[NOTICE ] rhsda: Results matching spotlight-product option: 2 of 4
[NOTICE ] rhsda: Invalid CVE queries: 1 of 4

CVE-2013-4113
  SEVERITY: Critical Impact
  DATE:     2013-07-11
  BUGZILLA: 983689
  FIXED_RELEASES matching 'eus':
   Red Hat Enterprise Linux EUS (v. 5.6 server) [php-5.1.6-27.el5_6.5]: RHSA-2013:1061
   Red Hat Enterprise Linux EUS (v. 5.6 server) [php53-5.3.3-1.el5_6.3]: RHSA-2013:1062
   Red Hat Enterprise Linux Extended Update Support 6.2 [php-5.3.3-3.el6_2.10]: RHSA-2013:1061
   Red Hat Enterprise Linux Extended Update Support 6.3 [php-5.3.3-14.el6_3.1]: RHSA-2013:1061

CVE-2014-3669
  SEVERITY: Moderate Impact
  DATE:     2014-09-18
  BUGZILLA: 1154500
  FIXED_RELEASES matching 'eus':
   Red Hat Enterprise Linux Extended Update Support 6.5 [php-5.3.3-27.el6_5.3]: RHSA-2015:0021
```

A `--urls` or `-u` option adds URLS

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642 --product eus --urls 2>/dev/null
CVE-2013-4113 (https://access.redhat.com/security/cve/CVE-2013-4113)
  SEVERITY: Critical Impact (https://access.redhat.com/security/updates/classification)
  DATE:     2013-07-11
  BUGZILLA: https://bugzilla.redhat.com/show_bug.cgi?id=983689
  FIXED_RELEASES matching 'eus':
   Red Hat Enterprise Linux EUS (v. 5.6 server) [php-5.1.6-27.el5_6.5]: https://access.redhat.com/errata/RHSA-2013:1061
   Red Hat Enterprise Linux EUS (v. 5.6 server) [php53-5.3.3-1.el5_6.3]: https://access.redhat.com/errata/RHSA-2013:1062
   Red Hat Enterprise Linux Extended Update Support 6.2 [php-5.3.3-3.el6_2.10]: https://access.redhat.com/errata/RHSA-2013:1061
   Red Hat Enterprise Linux Extended Update Support 6.3 [php-5.3.3-14.el6_3.1]: https://access.redhat.com/errata/RHSA-2013:1061

CVE-2014-3669 (https://access.redhat.com/security/cve/CVE-2014-3669)
  SEVERITY: Moderate Impact (https://access.redhat.com/security/updates/classification)
  DATE:     2014-09-18
  BUGZILLA: https://bugzilla.redhat.com/show_bug.cgi?id=1154500
  FIXED_RELEASES matching 'eus':
   Red Hat Enterprise Linux Extended Update Support 6.5 [php-5.3.3-27.el6_5.3]: https://access.redhat.com/errata/RHSA-2015:0021
```

CVEs can also be extracted from stdin with `--extract-stdin` (`-0`) which uses case-insensitive regular expressions; note that the following examples use `--count` for the sake of brevity

First example: pasting newline-separated CVEs with shell heredoc redirection

```
$ rhsecapi --extract-stdin --count <<EOF
> CVE-2016-5630 
> CVE-2016-5631 
> CVE-2016-5632 
> CVE-2016-5633 
> CVE-2016-5634 
> CVE-2016-5635 
> EOF
[NOTICE ] rhsda: Found 6 CVEs in stdin; 0 duplicates removed
[WARNING] rhsda: Stdin redirection suppresses term-width auto-detection; setting WIDTH to 70
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 6 of 6
```

Second example: piping in file(s) with `cat|` or file redirection (`< somefile`)

```
$ cat scan-results.csv | rhsecapi -0 -c
[NOTICE ] rhsda: Found 150 CVEs in stdin; 698 duplicates removed
[WARNING] rhsda: Stdin redirection suppresses term-width auto-detection; setting WIDTH to 70
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 148 of 150
[NOTICE ] rhsda: Invalid CVE queries: 2 of 150
```

The CVE retrieval process is multi-threaded; with CPUcount < 4, it defaults to 4 threads; with CPUcount > 4, it defaults to `CPUcount * 2` 

```
$ grep processor /proc/cpuinfo | wc -l
4

$ rhsecapi --help | grep -A1 threads
  -t, --threads THREDS  Set number of concurrent worker threads to allow when
                        making CVE queries (default on this system: 8)

$ time rhsecapi --q-empty --q-pagesize 48 --extract-search >/dev/null
[NOTICE ] rhsda: 48 CVEs found with search query
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 48 of 48

real	0m3.872s
user	0m0.825s
sys	0m0.055s
```

## Installation

- **Option 1 for RHEL6, RHEL7, Fedora: Install rsaw's yum repo and then rhsecapi rpm**
  1. If you don't already have rsaw's yum repo due to xsos or upvm or something else, set it up with the following command: `yum install http://people.redhat.com/rsawhill/rpms/latest-rsawaroha-release.rpm`
  1. Install rhsecapi: `yum install rhsecapi`
  1. Execute: `rhsecapi`

- **Option 2: Download latest release from github and run it**
  1. Go to [Releases](https://github.com/ryran/rhsecapi/releases)
  1. Download and extract the latest release
  1. Optional: `mkdir -p ~/bin; ln -sv /PATH/TO/rhsecapi.py ~/bin/rhsecapi`
  1. Execute: `rhsecapi`

  
## Abbreviated usage

```
$ rhsecapi -h
usage: rhsecapi [--q-before YEAR-MM-DD] [--q-after YEAR-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT] [--q-package PKG]
                [--q-cwe CWEID] [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [--q-iava IAVA] [-s] [-0] [-f FIELDS | -a | -m]
                [--product PRODUCT] [-j] [-u] [-w [WIDTH]] [-c]
                [-l {debug,info,notice,warning}] [-t THREDS] [-p] [--dryrun]
                [-E [DAYS]] [-h] [--help]
                [CVE [CVE ...]]

Run rhsecapi --help for full help page

VERSION:
  rhsecapi v1.0.0_rc2 last mod 2016/18/10
  See <http://github.com/ryran/rhsecapi> to report bugs or RFEs
```

## BASH intelligent tab-completion

```
$ rhsecapi --[TabTab]
--all-fields      --help            --product         --q-cvss3         --q-pagesize
--count           --json            --q-advisory      --q-cwe           --q-raw
--dryrun          --loglevel        --q-after         --q-empty         --q-severity
--extract-search  --most-fields     --q-before        --q-iava          --threads
--extract-stdin   --pastebin        --q-bug           --q-package       --urls
--fields          --pexpire         --q-cvss          --q-pagenum       --wrap
```

## Field display

Add some fields to the defaults with `--fields +field[,field]...` and note that arguments to `--fields` are handled in a case-insensitive way

```
$ rhsecapi CVE-2016-6302 --fields +CWE,cvss3 --loglevel info
[INFO   ] rhsda: Using 1 worker threads
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json' ...
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-6302
  SEVERITY: Moderate Impact
  DATE:     2016-08-23
  CWE:      CWE-190->CWE-125
  CVSS3:    5.9 (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
  BUGZILLA: 1369855
  FIXED_RELEASES:
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-48.el6_8.3]: RHSA-2016:1940
   Red Hat Enterprise Linux 7 [openssl-1:1.0.1e-51.el7_2.7]: RHSA-2016:1940
  FIX_STATES:
   Affected: Red Hat JBoss Core Services 1 [openssl]
   Affected: Red Hat JBoss EAP 6 [openssl]
   Will not fix: Red Hat JBoss EWS 1 [openssl]
   Will not fix: Red Hat JBoss EWS 2 [openssl]
   Affected: Red Hat JBoss Web Server 3.0 [openssl]
   Not affected: Red Hat Enterprise Linux 5 [openssl097a]
   Not affected: Red Hat Enterprise Linux 5 [openssl]
   Not affected: Red Hat Enterprise Linux 6 [openssl098e]
   Not affected: Red Hat Enterprise Linux 7 [OVMF]
   Not affected: Red Hat Enterprise Linux 7 [openssl098e]
```

Remove some fields from the list of all fields with `--fields ^field[,field]...`

```
$ rhsecapi CVE-2016-6302 -f ^FIXED_reLEASES,fIx_sTaTes,DETAILS -l info
[INFO   ] rhsda: Using 1 worker threads
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json' ...
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-6302
  SEVERITY: Moderate Impact
  DATE:     2016-08-23
  IAVA:     2016-A-0262
  CWE:      CWE-190->CWE-125
  CVSS:     4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P)
  CVSS3:    5.9 (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
  BUGZILLA: 1369855
  UPSTREAM_FIX:  openssl 1.0.1u, openssl 1.0.2i
  REFERENCES:
   https://www.openssl.org/news/secadv/20160922.txt
```

Note that there are also two presets: `--all-fields` and `--most-fields`

```
$ rhsecapi CVE-2016-6302 --loglevel debug --most-fields 2>&1 | grep fields
[DEBUG  ] rhsda: Requested fields string: 'MOST'
[DEBUG  ] rhsda: Enabled fields: 'threat_severity, public_date, iava, cwe, cvss, cvss3, bugzilla, upstream_fix, affected_release, package_state'

$ rhsecapi CVE-2016-6302 --loglevel debug --all-fields 2>&1 | grep fields
[DEBUG  ] rhsda: Requested fields string: 'ALL'
[DEBUG  ] rhsda: Enabled fields: 'threat_severity, public_date, iava, cwe, cvss, cvss3, bugzilla, acknowledgement, details, statement, mitigation, upstream_fix, references, affected_release, package_state'
```

## Find CVEs
The `--q-xxx` options can be combined to craft a search, listing CVEs via a single API call; add `--extract-search` (`-s`) to perform individual CVE queries against each CVE returned by the search 

### Empty search: list CVEs by public-date

```
 $ rhsecapi --loglevel info --q-empty
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve.json' ...
[NOTICE ] rhsda: 1000 CVEs found with search query

CVE-2016-9401
CVE-2016-9372
CVE-2016-9066
CVE-2016-9064
CVE-2016-8635
CVE-2016-9374
... (output truncated for brevity of this README)
```

```
$ rhsecapi -l info --q-empty --q-pagesize 4 --q-pagenum 3
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve.json?per_page=5&page=3' ...
[NOTICE ] rhsda: 4 CVEs found with search query

CVE-2016-5297
CVE-2016-9376
CVE-2016-5290
CVE-2016-5291
```

```
$ rhsecapi --q-empty --q-pagesize 1 --extract-search --all-fields 
[NOTICE ] rhsda: 1 CVEs found with search query
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-9401
  SEVERITY: Low Impact
  DATE:     2016-11-17
  CWE:      CWE-416
  CVSS:     3.3 (AV:L/AC:M/Au:N/C:P/I:P/A:N)
  CVSS3:    4.4 (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N)
  BUGZILLA: 1396383
  DETAILS:  
   Details pending
  FIX_STATES:
   New: Red Hat Enterprise Linux 5 [bash]
   New: Red Hat Enterprise Linux 6 [bash]
   New: Red Hat Enterprise Linux 7 [bash]
```

### Find by attributes

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-10-01
[NOTICE ] rhsda: 6 CVEs found with search query

CVE-2015-3456
CVE-2015-0235
CVE-2014-3611
CVE-2014-3645
CVE-2014-3646
CVE-2014-3567
```

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-10-01 --count
[NOTICE ] rhsda: 6 CVEs found with search query
```

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-12-01 --q-severity critical --json
[NOTICE ] rhsda: 1 CVEs found with search query

[
  {
    "CVE": "CVE-2015-0235", 
    "CWE": "CWE-131->CWE-122", 
    "advisories": [
      "RHSA-2015:0090", 
      "RHSA-2015:0092", 
      "RHSA-2015:0126", 
      "RHSA-2015:0101", 
      "RHSA-2015:0099"
    ], 
    "affected_packages": [
      "glibc-2.5-123.el5_11.1", 
      "glibc-2.12-1.149.el6_6.5", 
      "rhev-hypervisor6-6.6-20150123.1.el6ev", 
      "glibc-2.17-55.el7_0.5", 
      "glibc-2.3.4-2.57.el4.2", 
      "glibc-2.5-107.el5_9.8", 
      "glibc-2.12-1.107.el6_4.7", 
      "glibc-2.12-1.132.el6_5.5", 
      "glibc-2.5-58.el5_6.6", 
      "glibc-2.12-1.47.el6_2.15"
    ], 
    "bugzilla": "1183461", 
    "cvss_score": 6.8, 
    "cvss_scoring_vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P", 
    "public_date": "2015-01-27T00:00:00+00:00", 
    "resource_url": "https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-0235.json", 
    "severity": "critical"
  }
]
```

```
$ rhsecapi --loglevel info --q-package rhev-hypervisor6 --q-after 2014-12-01 --q-severity critical --extract-search --product hypervisor
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve.json?after=2014-12-01&severity=critical&package=rhev-hypervisor6' ...
[NOTICE ] rhsda: 1 CVEs found with search query
[INFO   ] rhsda: Using 1 worker threads
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-0235.json' ...
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1
[NOTICE ] rhsda: Results matching spotlight-product option: 1 of 1

CVE-2015-0235
  SEVERITY: Critical Impact
  DATE:     2015-01-27
  BUGZILLA: 1183461
  FIXED_RELEASES matching 'hypervisor':
   RHEV Hypervisor for RHEL-6 [rhev-hypervisor6-6.6-20150123.1.el6ev]: RHSA-2015:0126
```


### Find CVEs by IAVA

```
$ rhsecapi --loglevel info --q-iava not-a-real-iava
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/iavmmapper/api/iava/' ...
[ERROR  ] rhsda: Login error

IAVA→CVE mapping data is not provided by the public RH Security Data API.
Instead, this uses the IAVM Mapper App (access.redhat.com/labs/iavmmapper).

Access to this data requires RH Customer Portal credentials be provided.
Create a ~/.netrc with the following contents:

machine access.redhat.com
  login YOUR-CUSTOMER-PORTAL-LOGIN
  password YOUR_PASSWORD_HERE

For help, open an issue at http://github.com/ryran/rhsecapi
Or post a comment at https://access.redhat.com/discussions/2713931

$ vim ~/.netrc

$ rhsecapi --loglevel info --q-iava not-a-real-iava
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/iavmmapper/api/iava/' ...
[ERROR  ] rhsda: IAVM Mapper app main index doesn't contain 'not-a-real-iava'

For help, open an issue at http://github.com/ryran/rhsecapi
Or post a comment at https://access.redhat.com/discussions/2713931
```

```
$ rhsecapi --q-iava 2016-A-0287
[NOTICE ] rhsda: 4 CVEs found with search

CVE-2015-7940
CVE-2016-2107
CVE-2016-4979
CVE-2016-5604
```

```
$ rhsecapi --q-iava 2016-A-0287 --json --loglevel warning 

{
  "IAVM": {
    "CVEs": {
      "CVENumber": [
        "CVE-2015-7940", 
        "CVE-2016-2107", 
        "CVE-2016-4979", 
        "CVE-2016-5604"
      ]
    }, 
    "S": {
      "IAVM": "2016-A-0287", 
      "Severity": "CAT I", 
      "Title": "Multiple Vulnerabilities in Oracle Enterprise Manager"
    }
  }
}
```

```
$ rhsecapi --q-iava 2016-A-0287 --loglevel debug --extract-search --product linux.6 --count
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/iavmmapper/api/iava/' ...
[DEBUG  ] rhsda: Return status: '200'; Content-Type: 'application/json; charset=utf-8'
[DEBUG  ] rhsda: IAVM Mapper app main index contains '2016-A-0287'
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/iavmmapper/api/iava/2016-A-0287' ...
[DEBUG  ] rhsda: Return status: '200'; Content-Type: 'application/json; charset=utf-8'
[NOTICE ] rhsda: 4 CVEs found with search
[INFO   ] rhsda: Using 4 worker threads
[DEBUG  ] rhsda: Requested fields string: 'BASE'
[DEBUG  ] rhsda: Enabled fields: 'threat_severity, public_date, bugzilla, affected_release, package_state'
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-7940.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-2107.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-4979.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5604.json' ...
[DEBUG  ] rhsda: Return status: '200'; Content-Type: 'application/json; charset=utf-8'
[DEBUG  ] rhsda: Return status: '200'; Content-Type: 'application/json; charset=utf-8'
[INFO   ] rhsda: Hiding CVE-2015-7940 due to negative product match
[DEBUG  ] rhsda: Return status: '200'; Content-Type: 'application/json; charset=utf-8'
[DEBUG  ] rhsda: Return status: '404'; Content-Type: 'text/html;charset=UTF-8'
[INFO   ] rhsda: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5604.json
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 3 of 4
[NOTICE ] rhsda: Results matching spotlight-product option: 2 of 4
[NOTICE ] rhsda: Invalid CVE queries: 1 of 4
```

```
$ rhsecapi --q-iava 2016-A-0287 --extract-search --product linux.6
[NOTICE ] rhsda: 4 CVEs found with search
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 3 of 4
[NOTICE ] rhsda: Results matching spotlight-product option: 2 of 4
[NOTICE ] rhsda: Invalid CVE queries: 1 of 4

CVE-2016-2107
  SEVERITY: Moderate Impact
  DATE:     2016-05-03
  BUGZILLA: 1331426
  FIXED_RELEASES matching 'linux.6':
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-48.el6_8.1]: RHSA-2016:0996
  FIX_STATES matching 'linux.6':
   Not affected: Red Hat Enterprise Linux 6 [openssl098e]

CVE-2016-4979
  SEVERITY: Moderate Impact
  DATE:     2016-07-05
  BUGZILLA: 1352476
  FIX_STATES matching 'linux.6':
   Not affected: Red Hat Enterprise Linux 6 [httpd]
```


## Advanced: find unresolved CVEs for a specific package in a specific product

- **Question:**

  > *Are there any unresolved CVEs for the glibc package in RHEL6?*

- **Recipe:**

  1. Start with a package search (`--q-package glibc`)
  1. Extract the CVEs (`--extract-search` or `-s`)
  1. Use spotlight-product option to narrow results (`--product 'linux 6'`)
    - Note: this option treats input as a case-insensitive extended regex and matches it against two product fields in the json data; see `--help` entry for `--product`
  1. Restrict field display to exclude the `FIXED_RELEASES` field, e.g., `-f ^releases` OR specify customized list that includes `FIX_STATES` and not `FIXED_RELEASES` (e.g., `-f severity,date,cvss,states`)
    - Note: fields parsed by `--fields`/`-f` are case-insensitive and there are multiple synonymous aliases for the RELASES & STATES fields; see `--help` entry for `--fields`

- **Example:**

  ```
  $ rhsecapi --q-package glibc --extract-search --product 'linux 6' -f bugzilla,fix_states,severity,cvss
  [NOTICE ] rhsda: 41 CVEs found with search query
  [NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 41 of 41
  [NOTICE ] rhsda: Results matching spotlight-product option: 8 of 41

  CVE-2016-3075
    SEVERITY: Low Impact
    CVSS:     3.7 (AV:L/AC:H/Au:N/C:P/I:P/A:P)
    BUGZILLA: 1321866
    FIX_STATES matching 'linux 6':
     Will not fix: Red Hat Enterprise Linux 6 [compat-glibc]
     Will not fix: Red Hat Enterprise Linux 6 [glibc]

  CVE-2015-5277
    SEVERITY: Important Impact
    CVSS:     3.7 (AV:L/AC:H/Au:N/C:P/I:P/A:P)
    BUGZILLA: 1262914
    FIX_STATES matching 'linux 6':
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2014-8121
    SEVERITY: Low Impact
    CVSS:     3.3 (AV:A/AC:L/Au:N/C:N/I:N/A:P)
    BUGZILLA: 1165192
    FIX_STATES matching 'linux 6':
     Fix deferred: Red Hat Enterprise Linux 6 [glibc]

  CVE-2015-1472
    SEVERITY: Low Impact
    CVSS:     2.6 (AV:L/AC:H/Au:N/C:P/I:N/A:P)
    BUGZILLA: 1188235
    FIX_STATES matching 'linux 6':
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2015-1473
    SEVERITY: Low Impact
    CVSS:     2.6 (AV:L/AC:H/Au:N/C:P/I:N/A:P)
    BUGZILLA: 1209105
    FIX_STATES matching 'linux 6':
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2010-0296
    SEVERITY: Low Impact
    CVSS:     4.3 (AV:L/AC:L/Au:S/C:P/I:P/A:P)
    BUGZILLA: 559579
    FIX_STATES matching 'linux 6':
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2010-0830
    SEVERITY: Low Impact
    CVSS:     3.7 (AV:L/AC:H/Au:N/C:P/I:P/A:P)
    BUGZILLA: 599056
    FIX_STATES matching 'linux 6':
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2009-5029
    SEVERITY: Moderate Impact
    CVSS:     6.5 (AV:N/AC:L/Au:S/C:P/I:P/A:P)
    BUGZILLA: 761245
    FIX_STATES matching 'linux 6':
     Affected: Red Hat Enterprise Linux 6 [compat-glibc]
  ```


## Full help page

```
usage: rhsecapi [--q-before YEAR-MM-DD] [--q-after YEAR-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT] [--q-package PKG]
                [--q-cwe CWEID] [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [--q-iava IAVA] [-s] [-0] [-f FIELDS | -a | -m]
                [--product PRODUCT] [-j] [-u] [-w [WIDTH]] [-c]
                [-l {debug,info,notice,warning}] [-t THREDS] [-p] [--dryrun]
                [-E [DAYS]] [-h] [--help]
                [CVE [CVE ...]]

Make queries against the Red Hat Security Data API
Original announcement: https://access.redhat.com/blogs/766093/posts/2387601
Docs: https://access.redhat.com/documentation/en/red-hat-security-data-api/

FIND CVES BY ATTRIBUTE:
  --q-before YEAR-MM-DD
                        Narrow down results to before a certain time period
  --q-after YEAR-MM-DD  Narrow down results to after a certain time period
  --q-bug BZID          Narrow down results by Bugzilla ID (specify one or
                        more, e.g.: '1326598,1084875')
  --q-advisory RHSA     Narrow down results by errata advisory (specify one or
                        more, e.g.: 'RHSA-2016:0614,RHSA-2016:0610')
  --q-severity IMPACT   Narrow down results by severity rating (specify one of
                        'low', 'moderate', 'important', or 'critical')
  --q-package PKG       Narrow down results by package name (e.g.: 'samba' or
                        'thunderbird')
  --q-cwe CWEID         Narrow down results by CWE ID (specify one or more,
                        e.g.: '295,300')
  --q-cvss SCORE        Narrow down results by CVSS base score (e.g.: '8.0')
  --q-cvss3 SCORE       Narrow down results by CVSSv3 base score (e.g.: '5.1')
  --q-empty             Allow performing an empty search; when used with no
                        other --q-xxx options, this will return the first 1000
                        of the most recent CVEs (subject to below PAGESZ &
                        PAGENUM)
  --q-pagesize PAGESZ   Set a cap on the number of results that will be
                        returned (default: 1000)
  --q-pagenum PAGENUM   Select what page number to return (default: 1); only
                        relevant when there are more than PAGESZ results
  --q-raw RAWQUERY      Narrow down results by RAWQUERY (e.g.: '--q-raw a=x
                        --q-raw b=y'); this allows passing arbitrary params
                        (e.g. something new that is unsupported by rhsecapi)

FIND CVES BY IAVA:
  --q-iava IAVA         Narrow down results by IAVA number (e.g.:
                        '2016-A-0293'); note however that this feature is not
                        provided by the Red Hat Security Data API and thus:
                        (1) it requires login to the Red Hat Customer Portal
                        and (2) it cannot be used in concert with any of the
                        above search parameters

QUERY SPECIFIC CVES:
  CVE                   Retrieve a CVE or space-separated list of CVEs (e.g.:
                        'CVE-2016-5387')
  -s, --extract-search  Extract CVEs them from search query (as initiated by
                        at least one of the --q-xxx options)
  -0, --extract-stdin   Extract CVEs from stdin (CVEs will be matched by case-
                        insensitive regex 'CVE-[0-9]{4}-[0-9]{4,}' and
                        duplicates will be discarded); note that terminal
                        width auto-detection is not possible in this mode and
                        WIDTH defaults to '70' (but can be overridden with '--
                        width')

CVE DISPLAY OPTIONS:
  -f, --fields FIELDS   Customize field display via comma-separated case-
                        insensitive list (default: threat_severity,
                        public_date, bugzilla, affected_release,
                        package_state); see --all-fields option for full list
                        of official API-provided fields; shorter field
                        aliases: threat_severity → severity, public_date →
                        date, affected_release → fixed_releases or fixed or
                        releases, package_state → fix_states or states;
                        optionally prepend FIELDS with plus (+) sign to add
                        fields to the default (e.g., '-f +iava,cvss3') or a
                        caret (^) to remove fields from all-fields (e.g., '-f
                        ^mitigation,severity')
  -a, --all-fields      Display all supported fields (currently:
                        threat_severity, public_date, iava, cwe, cvss, cvss3,
                        bugzilla, acknowledgement, details, statement,
                        mitigation, upstream_fix, references,
                        affected_release, package_state)
  -m, --most-fields     Display all fields mentioned above except the heavy-
                        text ones -- (excludes: acknowledgement, details,
                        statement, mitigation, references)
  --product PRODUCT     Spotlight a particular PRODUCT via case-insensitive
                        regex; this hides CVEs where 'FIXED_RELEASES' or
                        'FIX_STATES' don't have an item with 'cpe' (e.g.
                        'cpe:/o:redhat:enterprise_linux:7') or 'product_name'
                        (e.g. 'Red Hat Enterprise Linux 7') matching PRODUCT;
                        this also hides all items in 'FIXED_RELEASES' &
                        'FIX_STATES' that don't match PRODUCT
  -j, --json            Print full & raw JSON output
  -u, --urls            Print URLs for all relevant fields

GENERAL OPTIONS:
  -w, --wrap [WIDTH]    Change wrap-width of long fields (acknowledgement,
                        details, statement, mitigation, references) in non-
                        json output (default: wrapping WIDTH equivalent to
                        TERMWIDTH-2 unless using '--pastebin' where default
                        WIDTH is '168'; specify '0' to disable wrapping; WIDTH
                        defaults to '70' if option is used but WIDTH is
                        omitted)
  -c, --count           Exit after printing CVE counts
  -l, --loglevel {debug,info,notice,warning}
                        Configure logging level threshold; lower from the
                        default of 'notice' to see extra details printed to
                        stderr
  -t, --threads THREDS  Set number of concurrent worker threads to allow when
                        making CVE queries (default on this system: 8)
  -p, --pastebin        Send output to Fedora Project Pastebin
                        (paste.fedoraproject.org) and print only URL to stdout
  --dryrun              Skip CVE retrieval; this option only makes sense in
                        concert with --extract-stdin, for the purpose of
                        quickly getting a printable list of CVE ids from stdin
  -E, --pexpire [DAYS]  Set time in days after which paste will be deleted
                        (defaults to '28'; specify '0' to disable expiration;
                        DAYS defaults to '1' if option is used but DAYS is
                        omitted)
  -h                    Show short usage summary and exit
  --help                Show this help message and exit

VERSION:
  rhsecapi v1.0.0_rc2 last mod 2016/18/10
  See <http://github.com/ryran/rhsecapi> to report bugs or RFEs
```


## Working with backend rhsda library

The `rhsda` library does all the work of interfacing with the API. If run directly, it tries to find CVEs on stdin.

```
$ echo CVE-2016-9401 CVE-2016-9372 CVE-2016-8635 | python rhsda.py
[NOTICE ] rhsda: Found 3 CVEs in stdin; 0 duplicates removed
[INFO   ] rhsda: Using 3 worker threads
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-9401.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8635.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-9372.json' ...
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 3 of 3
CVE-2016-9401
  SEVERITY: Low Impact
  DATE:     2016-11-17
  CWE:      CWE-416
  CVSS:     3.3 (AV:L/AC:M/Au:N/C:P/I:P/A:N)
  CVSS3:    4.4 (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N)
  BUGZILLA: 1396383
  DETAILS:  
   Details pending
  FIX_STATES:
   New: Red Hat Enterprise Linux 5 [bash]
   New: Red Hat Enterprise Linux 6 [bash]
   New: Red Hat Enterprise Linux 7 [bash]

CVE-2016-8635
  SEVERITY: Moderate Impact
  DATE:     2016-11-16
  CVSS:     4.3 (AV:N/AC:M/Au:N/C:P/I:N/A:N)
  CVSS3:    5.3 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
  BUGZILLA: 1391818
  ACKNOWLEDGEMENT:  
   This issue was discovered by Hubert Kario (Red Hat).
  DETAILS:  
   ** RESERVED ** This candidate has been reserved by an organization
   or individual that will use it when announcing a new security
   problem.  When the candidate has been publicized, the details for
   this candidate will be provided.  It was found that Diffie Hellman
   Client key exchange handling in NSS was vulnerable to small
   subgroup confinement attack. An attacker could use this flaw to
   recover private keys by confining the client DH key to small
   subgroup of the desired group.
  FIXED_RELEASES:
   Red Hat Enterprise Linux 5 [nss-3.21.3-2.el5_11]: RHSA-2016:2779
   Red Hat Enterprise Linux 6 [nss-3.21.3-2.el6_8]: RHSA-2016:2779
   Red Hat Enterprise Linux 7 [nss-3.21.3-2.el7_3]: RHSA-2016:2779

CVE-2016-9372
  SEVERITY: Moderate Impact
  DATE:     2016-11-16
  CVSS:     4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P)
  CVSS3:    5.9 (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
  BUGZILLA: 1396409
  DETAILS:  
   Details pending
  UPSTREAM_FIX:  wireshark 2.2.2
  REFERENCES:
   https://www.wireshark.org/security/wnpa-sec-2016-58.html
  FIX_STATES:
   Will not fix: Red Hat Enterprise Linux 5 [wireshark]
   Will not fix: Red Hat Enterprise Linux 6 [wireshark]
   Will not fix: Red Hat Enterprise Linux 7 [wireshark]
```

To plug it into, e.g., a web-app, check the help

```
$ python
>>> import rhsda
>>> help(rhsda)
Help on module rhsda:

NAME
    rhsda

FILE
    /usr/share/rhsecapi/rhsda.py

DESCRIPTION
    # -*- coding: utf-8 -*-
    #-------------------------------------------------------------------------------
    # Copyright 2016 Ryan Sawhill Aroha <rsaw@redhat.com> and rhsecapi contributors
    #
    #    This program is free software: you can redistribute it and/or modify
    #    it under the terms of the GNU General Public License as published by
    #    the Free Software Foundation, either version 3 of the License, or
    #    (at your option) any later version.
    #
    #    This program is distributed in the hope that it will be useful,
    #    but WITHOUT ANY WARRANTY; without even the implied warranty of
    #    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    #    General Public License <gnu.org/licenses/gpl.html> for more details.
    #-------------------------------------------------------------------------------

CLASSES
    ApiClient
    
    class ApiClient
     |  Portable object to interface with the Red Hat Security Data API.
     |  
     |  https://access.redhat.com/documentation/en/red-hat-security-data-api/
     |  
     |  Methods defined here:
     |  
     |  __init__(self, logLevel='notice')
     |  
     |  cve_search_query(self, params, outFormat='list')
     |      Perform a CVE search query.
     |      
     |      ON *OUTFORMAT*:
     |      
     |      Setting to "list" returns list of found CVE ids.
     |      Setting to "plaintext" returns str object containing new-line separated CVE ids.
     |      Setting to "json" returns list object containing original JSON.
     |      Setting to "jsonpretty" returns str object containing prettified JSON.
     |  
     |  find_cves(self, params=None, outFormat='json', before=None, after=None, bug=None, advisory=None, severity=None, package=None, cwe=None, cvss_score=None, cvss3_score=None, page=None, per_page=None)
     |      Find CVEs by recent or attributes.
     |      
     |      Provides an index to recent CVEs when no parameters are passed. Returns a
     |      convenience object as response with minimal attributes. 
     |      
     |      With *outFormat* of "json", returns JSON object.
     |      With *outFormat* of "xml", returns unformatted XML as string.
     |      If *params* dict is passed, additional parameters are ignored.
     |  
     |  find_cvrfs(self, params=None, outFormat='json', before=None, after=None, bug=None, cve=None, severity=None, package=None, page=None, per_page=None)
     |      Find CVRF documents by recent or attributes.
     |      
     |      Provides an index to recent CVRF documents with a summary of their contents,
     |      when no parameters are passed. Returns a convenience object as the response with
     |      minimal attributes. 
     |      
     |      With *outFormat* of "json", returns JSON object.
     |      With *outFormat* of "xml", returns unformatted XML as string.
     |      If *params* dict is passed, additional parameters are ignored.
     |  
     |  find_ovals(self, params=None, outFormat='json', before=None, after=None, bug=None, cve=None, severity=None, page=None, per_page=None)
     |      Find OVAL definitions by recent or attributes.
     |      
     |      Provides an index to recent OVAL definitions with a summary of their contents,
     |      when no parameters are passed. Returns a convenience object as the response with
     |      minimal attributes.
     |      
     |      With *outFormat* of "json", returns JSON object.
     |      With *outFormat* of "xml", returns unformatted XML as string.
     |      If *params* dict is passed, additional parameters are ignored.
     |  
     |  get_cve(self, cve, outFormat='json')
     |      Retrieve full details of a CVE.
     |  
     |  get_cvrf(self, rhsa, outFormat='json')
     |      Retrieve CVRF details for an RHSA.
     |  
     |  get_cvrf_oval(self, rhsa, outFormat='json')
     |      Retrieve CVRF-OVAL details for an RHSA.
     |  
     |  get_iava(self, iavaId)
     |      Validate IAVA number and return json.
     |  
     |  get_oval(self, rhsa, outFormat='json')
     |      Retrieve OVAL details for an RHSA.
     |  
     |  mget_cves(self, cves, numThreads=0, onlyCount=False, outFormat='plaintext', urls=False, fields='ALL', wrapWidth=70, product=None, timeout=300)
     |      Use multi-threading to lookup a list of CVEs and return text output.
     |      
     |      *cves*:       A list of CVE ids or a str obj from which to regex CVE ids
     |      *numThreads*: Number of concurrent worker threads; 0 == CPUs*2
     |      *onlyCount*:  Whether to exit after simply logging number of valid/invalid CVEs
     |      *outFormat*:  Control output format ("plaintext", "json", or "jsonpretty")
     |      *urls*:       Whether to add extra URLs to certain fields
     |      *fields*:     Customize which fields are displayed by passing comma-sep string
     |      *wrapWidth*:  Width for long fields; 1 auto-detects based on terminal size
     |      *product*:    Restrict display of CVEs based on product-matching regex
     |      *timeout*:    Total ammount of time to wait for all CVEs to be retrieved
     |      
     |      ON *CVES*:
     |      
     |      If *cves* is a list, each item in the list will be retrieved as a CVE.
     |      If *cves* is a string or file object, it will be regex-parsed line by line and
     |      all CVE ids will be extracted into a list.
     |      In all cases, character-case is irrelevant.
     |      
     |      ON *OUTFORMAT*:
     |      
     |      Setting to "plaintext" returns str object containing formatted output.
     |      Setting to "json" returns list object (i.e., original JSON)
     |      Setting to "jsonpretty" returns str object containing prettified JSON
     |      
     |      ON *FIELDS*:
     |      
     |      librhsecapi.cveFields.all is a list obj of supported fields, i.e.:
     |          threat_severity, public_date, iava, cwe, cvss, cvss3, bugzilla,
     |          acknowledgement, details, statement, mitigation, upstream_fix, references,
     |          affected_release, package_state
     |      
     |      librhsecapi.cveFields.most is a list obj that excludes text-heavy fields, like:
     |          acknowledgement, details, statement, mitigation, references
     |      
     |      librhsecapi.cveFields.base is a list obj of the most important fields, i.e.:
     |          threat_severity, public_date, bugzilla, affected_release, package_state
     |      
     |      There is a group-alias for each of these, so you can do:
     |          fields="ALL"
     |          fields="MOST"
     |          fields="BASE"
     |      
     |      Also note that some friendly aliases are supported, e.g.:
     |          threat_severity → severity
     |          public_date → date
     |          affected_release → fixed_releases or fixed or releases
     |          package_state → fix_states or states
     |      
     |      Note that the *fields* string can be prepended with "+" or "^" to signify
     |      adding to cveFields.base or removing from cveFields.all, e.g.:
     |          fields="+cvss,cwe,statement"
     |          fields="^releases,mitigation"
     |      
     |      Finally: *fields* is case-insensitive.

FUNCTIONS
    extract_cves_from_input(obj)
        Use case-insensitive regex to extract CVE ids from input object.
        
        *obj* can be a list, a file, or a string.
        
        A list of CVEs is returned.
    
    jprint(jsoninput, printOutput=True)
        Pretty-print jsoninput.

DATA
    consolehandler = <logging.StreamHandler object>
    cveFields = Namespace(aliases={'severity': 'threat_severity'...tails',...
    cve_regex = <_sre.SRE_Pattern object>
    cve_regex_string = 'CVE-[0-9]{4}-[0-9]{4,}'
    logger = <logging.Logger object>
    numThreadsDefault = 8
    print_function = _Feature((2, 6, 0, 'alpha', 2), (3, 0, 0, 'alpha', 0)...

(END)
```

As can be seen above, an `rhsda.ApiClient` class does most of the work. Simple methods for all operations laid out in the upstream documentation are available, allowing receipt of plain json/xml.

```
>>> a = rhsda.ApiClient()

>>> json = a.find_cves(after='2015-01-01', before='2015-02-01')
[NOTICE ] rhsda: 232 CVEs found with search query

>>> json = a.find_cves(params={'after':'2015-01-01', 'before':'2015-02-01'})
[NOTICE ] rhsda: 232 CVEs found with search query

>>> json = a.find_cvrfs(after='2015-01-01', before='2015-02-01')
[NOTICE ] rhsda: 50 CVRFs found with search query

>>> json = a.find_ovals(after='2015-01-01', before='2015-02-01')
[NOTICE ] rhsda: 20 OVALs found with search query

>>> print(a.get_cve("CVE-2016-5773", outFormat='xml'))
<Vulnerability name="CVE-2016-5773">
 <DocumentDistribution xml:lang='en'>
Copyright © 2012 Red Hat, Inc. All rights reserved.
</DocumentDistribution>
  <ThreatSeverity>Moderate</ThreatSeverity>
  <PublicDate>2016-06-23T00:00:00</PublicDate>
  <Bugzilla id="1351179" url="https://bugzilla.redhat.com/show_bug.cgi?id=1351179" xml:lang="en:us">
CVE-2016-5773 php: ZipArchive class Use After Free Vulnerability in PHP's GC algorithm and unserialize
    </Bugzilla>
  <CVSS status="verified">
    <CVSSBaseScore>5.1</CVSSBaseScore>
    <CVSSScoringVector>AV:N/AC:H/Au:N/C:P/I:P/A:P</CVSSScoringVector>
  </CVSS>
  <CVSS3 status="verified">
    <CVSS3BaseScore>5.6</CVSS3BaseScore>
    <CVSS3ScoringVector>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L</CVSS3ScoringVector>
  </CVSS3>
  <CWE>CWE-416</CWE>
  <Details xml:lang="en:us" source="Mitre">
php_zip.c in the zip extension in PHP before 5.5.37, 5.6.x before 5.6.23, and 7.x before 7.0.8 improperly interacts with the unserialize implementation and garbage collection, which allows remote attackers to execute arbitrary code or cause a denial of service (use-after-free and application crash) via crafted serialized data containing a ZipArchive object.
    </Details>
  <AffectedRelease cpe="cpe:/a:redhat:rhel_software_collections:2::el6">
    <ProductName>Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 6)</ProductName>
    <ReleaseDate>2016-11-15T00:00:00</ReleaseDate>
    <Advisory type="RHSA" url="https://rhn.redhat.com/errata/RHSA-2016-2750.html">RHSA-2016:2750</Advisory>
    <Package name="rh-php56-php">rh-php56-php-5.6.25-1.el6</Package>
  </AffectedRelease>
  <AffectedRelease cpe="cpe:/a:redhat:rhel_software_collections:2::el7">
    <ProductName>Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 7)</ProductName>
    <ReleaseDate>2016-11-15T00:00:00</ReleaseDate>
    <Advisory type="RHSA" url="https://rhn.redhat.com/errata/RHSA-2016-2750.html">RHSA-2016:2750</Advisory>
    <Package name="rh-php56-php">rh-php56-php-5.6.25-1.el7</Package>
  </AffectedRelease>
  <PackageState cpe="cpe:/o:redhat:enterprise_linux:5">
    <ProductName>Red Hat Enterprise Linux 5</ProductName>
    <FixState>Not affected</FixState>
    <PackageName>php</PackageName>
  </PackageState>
  <PackageState cpe="cpe:/o:redhat:enterprise_linux:5">
    <ProductName>Red Hat Enterprise Linux 5</ProductName>
    <FixState>Will not fix</FixState>
    <PackageName>php53</PackageName>
  </PackageState>
  <PackageState cpe="cpe:/o:redhat:enterprise_linux:6">
    <ProductName>Red Hat Enterprise Linux 6</ProductName>
    <FixState>Will not fix</FixState>
    <PackageName>php</PackageName>
  </PackageState>
  <PackageState cpe="cpe:/o:redhat:enterprise_linux:7">
    <ProductName>Red Hat Enterprise Linux 7</ProductName>
    <FixState>Will not fix</FixState>
    <PackageName>php</PackageName>
  </PackageState>
  <UpstreamFix>php 5.5.37, php 5.6.23</UpstreamFix>
</Vulnerability>
```

Also available: multi-threaded CVE retrieval (with default conversion to pretty-formatted plaintext) via `mget_cves()` method. Defaults to showing all fields.

```
>>> a = rhsda.ApiClient('info')    # (This increases the console loglevel [stderr])
>>> txt = a.mget_cves("CVE-2016-5387 CVE-2016-5392")
[NOTICE ] rhsda: Found 2 CVEs in input; 0 duplicates removed
[INFO   ] rhsda: Using 2 worker threads
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5392.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5387.json' ...
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 2 of 2
>>> print(txt)
CVE-2016-5392
  SEVERITY: Important Impact
  DATE:     2016-07-14
  CWE:      CWE-20
  CVSS:     6.8 (AV:N/AC:L/Au:S/C:C/I:N/A:N)
  CVSS3:    6.5 (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
  BUGZILLA: 1356195
  ACKNOWLEDGEMENT:  
   This issue was discovered by Yanping Zhang (Red Hat).
  DETAILS:  
   The API server in Kubernetes, as used in Red Hat OpenShift
   Enterprise 3.2, in a multi tenant environment allows remote
   authenticated users with knowledge of other project names to obtain
   sensitive project and user information via vectors related to the
   watch-cache list.  The Kubernetes API server contains a watch cache
   that speeds up performance. Due to an input validation error
   OpenShift Enterprise may return data for other users and projects
   when queried by a user. An attacker with knowledge of other project
   names could use this vulnerability to view their information.
  FIXED_RELEASES:
   Red Hat OpenShift Enterprise 3.2 [atomic-openshift-3.2.1.7-1.git.0.2702170.el7]: RHSA-2016:1427
  FIX_STATES:
   Affected: Red Hat OpenShift Enterprise 3 [Security]

CVE-2016-5387
  SEVERITY: Important Impact
  DATE:     2016-07-18
  IAVA:     2016-B-0160
  CWE:      CWE-20
  CVSS:     5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)
  CVSS3:    5.0 (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N)
  BUGZILLA: 1353755
  ACKNOWLEDGEMENT:  
   Red Hat would like to thank Scott Geary (VendHQ) for reporting this
   issue.
  DETAILS:  
   The Apache HTTP Server through 2.4.23 follows RFC 3875 section
   4.1.18 and therefore does not protect applications from the
   presence of untrusted client data in the HTTP_PROXY environment
   variable, which might allow remote attackers to redirect an
   application's outbound HTTP traffic to an arbitrary proxy server
   via a crafted Proxy header in an HTTP request, aka an "httpoxy"
   issue.  NOTE: the vendor states "This mitigation has been assigned
   the identifier CVE-2016-5387"; in other words, this is not a CVE ID
   for a vulnerability.  It was discovered that httpd used the value
   of the Proxy header from HTTP requests to initialize the HTTP_PROXY
   environment variable for CGI scripts, which in turn was incorrectly
   used by certain HTTP client implementations to configure the proxy
   for outgoing HTTP requests. A remote attacker could possibly use
   this flaw to redirect HTTP requests performed by a CGI script to an
   attacker-controlled proxy via a malicious HTTP request.
  UPSTREAM_FIX:  httpd 2.4.24, httpd 2.2.32
  REFERENCES:
   https://access.redhat.com/security/vulnerabilities/httpoxy
   https://httpoxy.org/
   https://www.apache.org/security/asf-httpoxy-response.txt
  FIXED_RELEASES:
   Red Hat Enterprise Linux 5 [httpd-2.2.3-92.el5_11]: RHSA-2016:1421
   Red Hat Enterprise Linux 6 [httpd-2.2.15-54.el6_8]: RHSA-2016:1421
   Red Hat Enterprise Linux 7 [httpd-2.4.6-40.el7_2.4]: RHSA-2016:1422
   Red Hat JBoss Core Services 1: RHSA-2016:1625
   Red Hat JBoss Core Services on RHEL 6 Server [jbcs-httpd24-httpd-2.4.6-77.SP1.jbcs.el6]: RHSA-2016:1851
   Red Hat JBoss Core Services on RHEL 7 Server [jbcs-httpd24-httpd-2.4.6-77.SP1.jbcs.el7]: RHSA-2016:1851
   Red Hat JBoss Enterprise Web Server 2 for RHEL 6 Server [httpd-2.2.26-54.ep6.el6]: RHSA-2016:1649
   Red Hat JBoss Enterprise Web Server 2 for RHEL 7 Server [httpd22-2.2.26-56.ep6.el7]: RHSA-2016:1648
   Red Hat JBoss Web Server 2.1: RHSA-2016:1650
   Red Hat JBoss Web Server 3.0: RHSA-2016:1624
   Red Hat JBoss Web Server 3.0 for RHEL 6: RHSA-2016:1636
   Red Hat JBoss Web Server 3.0 for RHEL 7: RHSA-2016:1635
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 6) [httpd24-httpd-2.4.18-11.el6]: RHSA-2016:1420
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 7) [httpd24-httpd-2.4.18-11.el7]: RHSA-2016:1420
  FIX_STATES:
   Affected: Red Hat JBoss EAP 6 [httpd22]
   Not affected: Red Hat JBoss EAP 7 [httpd22]
   Will not fix: Red Hat JBoss EWS 1 [httpd]
```

The `mget_cves()` method's `cves=` argument (the 1st kwarg) regex-finds CVEs in an input string:

```
>>> s = "Hello thar we need CVE-2016-5387 fixed as well as CVE-2016-5392(worst).\nAnd not to mention CVE-2016-2379,CVE-2016-1000219please."
>>> a = rhsda.ApiClient('info')
>>> json = a.mget_cves(s, outFormat='json')
[NOTICE ] rhsda: Found 4 CVEs in input; 0 duplicates removed
[INFO   ] rhsda: Using 4 worker threads
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5392.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-1000219.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5387.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-2379.json' ...
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 4 of 4
```

... or a file:

```
>>> a = rhsda.ApiClient()
>>> with open('scan-results.csv') as f:
...     txt = a.mget_cves(f)
... 
[NOTICE ] rhsda: Found 150 CVEs in input; 698 duplicates removed
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 148 of 150
[NOTICE ] rhsda: Invalid CVE queries: 2 of 150
```

Also of course a list is fine:

```
>>> L = ['CVE-2016-5387', 'CVE-2016-5392', 'CVE-2016-2379', 'CVE-2016-5773']
>>> print(a.mget_cves(L, fields='BASE', product='web.server.3'))
[INFO   ] rhsda: Using 4 worker threads
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5387.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5392.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-2379.json' ...
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5773.json' ...
[INFO   ] rhsda: Hiding CVE-2016-5392 due to negative product match
[INFO   ] rhsda: Hiding CVE-2016-2379 due to negative product match
[INFO   ] rhsda: Hiding CVE-2016-5773 due to negative product match
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 4 of 4
[NOTICE ] rhsda: Results matching spotlight-product option: 1 of 4
CVE-2016-5387
  SEVERITY: Important Impact
  DATE:     2016-07-18
  BUGZILLA: 1353755
  FIXED_RELEASES matching 'web.server.3':
   Red Hat JBoss Web Server 3.0: RHSA-2016:1624
   Red Hat JBoss Web Server 3.0 for RHEL 6: RHSA-2016:1636
   Red Hat JBoss Web Server 3.0 for RHEL 7: RHSA-2016:1635
```

There's also a convenience `cve_search_query()` method but that might go away.

```
>>> txt = a.cve_search_query({'after':'2015-01-01', 'before':'2015-02-01', 'per_page':5}, outFormat='plaintext')
[INFO   ] rhsda: Getting 'https://access.redhat.com/labs/securitydataapi/cve.json?per_page=5&after=2015-01-01&before=2015-02-01' ...
[NOTICE ] rhsda: 5 CVEs found with search query
>>> print(txt)
CVE-2014-0141
CVE-2015-1563
CVE-2015-8779
CVE-2014-9749
CVE-2015-0210
```
