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
- [Working with IAVAs](#working-with-iavas)
- [Advanced: find unresolved CVEs for a specific package in a specific product](#advanced-find-unresolved-cves-for-a-specific-package-in-a-specific-product)
- [Full help page](#full-help-page)
- [Working with backend rhsda library](#working-with-backend-rhsda-library)

## Simple CVE retrieval

Specify as many CVEs on cmdline as needed; certain details are printed to stderr -- e.g., in the following, the first 3 lines of output were sent to stderr

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642
[NOTICE ] rhsda: Found 4 CVEs on cmdline
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 3 of 4

CVE-2013-4113
  SEVERITY : Critical Impact
  DATE     : 2013-07-11
  BUGZILLA : 983689
  FIXED_RELEASES :
   Red Hat Enterprise Linux 5: [php-5.1.6-40.el5_9] via RHSA-2013:1049 (2013-07-12)
   Red Hat Enterprise Linux 5: [php53-5.3.3-13.el5_9.1] via RHSA-2013:1050 (2013-07-12)
   Red Hat Enterprise Linux 6: [php-5.3.3-23.el6_4] via RHSA-2013:1049 (2013-07-12)
   Red Hat Enterprise Linux Extended Lifecycle Support 3: [php-4.3.2-56.ent] via RHSA-2013:1063 (2013-07-15)
   Red Hat Enterprise Linux Extended Lifecycle Support 4: [php-4.3.9-3.37.el4] via RHSA-2013:1063 (2013-07-15)
   Red Hat Enterprise Linux EUS (v. 5.6 server): [php-5.1.6-27.el5_6.5] via RHSA-2013:1061 (2013-07-15)
   Red Hat Enterprise Linux EUS (v. 5.6 server): [php53-5.3.3-1.el5_6.3] via RHSA-2013:1062 (2013-07-15)
   Red Hat Enterprise Linux Extended Update Support 6.2: [php-5.3.3-3.el6_2.10] via RHSA-2013:1061 (2013-07-15)
   Red Hat Enterprise Linux Extended Update Support 6.3: [php-5.3.3-14.el6_3.1] via RHSA-2013:1061 (2013-07-15)
   Red Hat Enterprise Linux Long Life (v. 5.3 server): [php-5.1.6-23.4.el5_3] via RHSA-2013:1061 (2013-07-15)
  FIX_STATES :
   Not affected: Red Hat Enterprise Linux 7 [php]

CVE-2014-3669
  SEVERITY : Moderate Impact
  DATE     : 2014-09-18
  BUGZILLA : 1154500
  FIXED_RELEASES :
   Red Hat Enterprise Linux 5: [php53-5.3.3-26.el5_11] via RHSA-2014:1768 (2014-10-30)
   Red Hat Enterprise Linux 5: [php-5.1.6-45.el5_11] via RHSA-2014:1824 (2014-11-06)
   Red Hat Enterprise Linux 6: [php-5.3.3-40.el6_6] via RHSA-2014:1767 (2014-10-30)
   Red Hat Enterprise Linux 7: [php-5.4.16-23.el7_0.3] via RHSA-2014:1767 (2014-10-30)
   Red Hat Enterprise Linux Extended Update Support 6.5: [php-5.3.3-27.el6_5.3] via RHSA-2015:0021 (2015-01-08)
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 6): [php54-php-5.4.16-22.el6] via RHSA-2014:1765 (2014-10-30)
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 6): [php55-php-5.5.6-13.el6] via RHSA-2014:1766 (2014-10-30)
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 7): [php54-php-5.4.16-22.el7] via RHSA-2014:1765 (2014-10-30)
   Red Hat Software Collections 1 for Red Hat Enterprise Linux Server (v. 7): [php55-php-5.5.6-13.el7] via RHSA-2014:1766 (2014-10-30)

CVE-2004-0230
  BUGZILLA : No Bugzilla data
   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy

CVE-2015-4642
  Not present in Red Hat CVE database
  Try https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4642
```

A `--product` option allows spotlighting a particular product via a case-insenstive regex, e.g., here's the same exact command above spotlighting EUS products:

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642 --product eus
[NOTICE ] rhsda: Found 4 CVEs on cmdline
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 3 of 4
[NOTICE ] rhsda: Results matching spotlight-product option: 2 of 4

CVE-2013-4113
  SEVERITY : Critical Impact
  DATE     : 2013-07-11
  BUGZILLA : 983689
  FIXED_RELEASES matching 'eus' :
   Red Hat Enterprise Linux EUS (v. 5.6 server): [php-5.1.6-27.el5_6.5] via RHSA-2013:1061 (2013-07-15)
   Red Hat Enterprise Linux EUS (v. 5.6 server): [php53-5.3.3-1.el5_6.3] via RHSA-2013:1062 (2013-07-15)
   Red Hat Enterprise Linux Extended Update Support 6.2: [php-5.3.3-3.el6_2.10] via RHSA-2013:1061 (2013-07-15)
   Red Hat Enterprise Linux Extended Update Support 6.3: [php-5.3.3-14.el6_3.1] via RHSA-2013:1061 (2013-07-15)

CVE-2014-3669
  SEVERITY : Moderate Impact
  DATE     : 2014-09-18
  BUGZILLA : 1154500
  FIXED_RELEASES matching 'eus' :
   Red Hat Enterprise Linux Extended Update Support 6.5: [php-5.3.3-27.el6_5.3] via RHSA-2015:0021 (2015-01-08)
```

A `--urls` or `-u` option adds URLS

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642 --product eus --urls 2>/dev/null
CVE-2013-4113 (https://access.redhat.com/security/cve/CVE-2013-4113)
  SEVERITY : Critical Impact (https://access.redhat.com/security/updates/classification)
  DATE     : 2013-07-11
  BUGZILLA : https://bugzilla.redhat.com/show_bug.cgi?id=983689
  FIXED_RELEASES matching 'eus' :
   Red Hat Enterprise Linux EUS (v. 5.6 server): [php-5.1.6-27.el5_6.5] via https://access.redhat.com/errata/RHSA-2013:1061 (2013-07-15)
   Red Hat Enterprise Linux EUS (v. 5.6 server): [php53-5.3.3-1.el5_6.3] via https://access.redhat.com/errata/RHSA-2013:1062 (2013-07-15)
   Red Hat Enterprise Linux Extended Update Support 6.2: [php-5.3.3-3.el6_2.10] via https://access.redhat.com/errata/RHSA-2013:1061 (2013-07-15)
   Red Hat Enterprise Linux Extended Update Support 6.3: [php-5.3.3-14.el6_3.1] via https://access.redhat.com/errata/RHSA-2013:1061 (2013-07-15)

CVE-2014-3669 (https://access.redhat.com/security/cve/CVE-2014-3669)
  SEVERITY : Moderate Impact (https://access.redhat.com/security/updates/classification)
  DATE     : 2014-09-18
  BUGZILLA : https://bugzilla.redhat.com/show_bug.cgi?id=1154500
  FIXED_RELEASES matching 'eus' :
   Red Hat Enterprise Linux Extended Update Support 6.5: [php-5.3.3-27.el6_5.3] via https://access.redhat.com/errata/RHSA-2015:0021 (2015-01-08)
```

CVEs can also be extracted from stdin with `-0`/`--stdin` which uses case-insensitive regular expressions. Regex is also used to extract CVEs from cmdline args, so any arbitrary block of text can be dropped in as args if it's quoted. (Note that the following examples use `--count` for the sake of brevity.)

First example: pasting newline-separated CVEs with shell heredoc redirection

```
$ rhsecapi --stdin --count <<EOF
> CVE-2016-5630 
> CVE-2016-5631 
> CVE-2016-5632 
> CVE-2016-5633 
> CVE-2016-5634 
> CVE-2016-5635 
> EOF
[NOTICE ] rhsda: Found 6 CVEs on stdin
[WARNING] rhsda: Stdin redirection suppresses term-width auto-detection; setting WIDTH to 70
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 6 of 6
```

Second example: piping in file(s) with `cat|` or file redirection (`< somefile`) while at the same time pasting some comma-separate CVEs on the cmdline

```
$ cat scan-results.csv | rhsecapi --stdin "(CVE-2015-7501), (CVE-2015-5178, CVE-2015-5188, CVE-2015-5220) and (CVE-2013-4517, CVE-2013-6440, CVE-2014-0018)" --count 
[NOTICE ] rhsda: Found 7 CVEs on cmdline
[NOTICE ] rhsda: Found 150 CVEs on stdin; 698 duplicates removed
[WARNING] rhsda: Stdin redirection suppresses term-width auto-detection; setting WIDTH to 70
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 155 of 157
```

The CVE retrieval process is multi-threaded; with CPUcount <= 2, it defaults to 4 threads; otherwise, it defaults to `CPUcount * 2` 

```
$ grep processor /proc/cpuinfo | wc -l
4

$ rhsecapi --help | grep -A1 threads
  -t, --threads THREDS  Set number of concurrent worker threads to allow when
                        making CVE queries (default on this system: 8)

$ time rhsecapi --q-empty --q-pagesize 48 --extract-cves >/dev/null
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

- **Option 3: Install docker version**
  1. cd rhsecpai
  1. yum install docker for RHEL, can depend on your OS
  1. chmod +x install_docker.sh
  1. sudo ./install_docker.sh
  1. rhsecapi.sh CVE-2015-4642
  
## Abbreviated usage

```
$ rhsecapi -h
usage: rhsecapi [--q-before YYYY-MM-DD] [--q-after YYYY-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT]
                [--q-product PRODUCT] [--q-package PKG] [--q-cwe CWEID]
                [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [-i YYYY-?-NNNN] [-x] [-0] [-f FIELDS | -a | -m] [-p PRODUCT]
                [-j] [-u] [-w [WIDTH]] [-c] [-l {debug,info,notice,warning}]
                [-t THREDS] [-P] [-E [DAYS]] [--dryrun] [-h] [--help]
                [CVE-YYYY-NNNN [CVE-YYYY-NNNN ...]]

Run rhsecapi --help for full help page

VERSION:
  rhsecapi v1.0.0_rc10 last mod 2017/01/05
  See <http://github.com/ryran/rhsecapi> to report bugs or RFEs
```

## BASH intelligent tab-completion

```
$ rhsecapi --[TabTab]
--all-fields    --json          --q-after       --q-package     --threads
--count         --loglevel      --q-before      --q-pagenum     --urls
--dryrun        --most-fields   --q-bug         --q-pagesize    --wrap
--extract-cves  --pastebin      --q-cvss        --q-product     
--fields        --pexpire       --q-cvss3       --q-raw         
--help          --product       --q-cwe         --q-severity    
--iava          --q-advisory    --q-empty       --stdin         
```

## Field display

Add some fields to the defaults with `--fields +field[,field]...` and note that arguments to `--fields` are handled in a case-insensitive way

```
$ rhsecapi CVE-2016-6302 --fields +CWE,cvss3 --loglevel info
[NOTICE ] rhsda: Found 1 CVEs on cmdline
[INFO   ] rhsda: Using 1 worker threads
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-6302
  SEVERITY : Moderate Impact
  DATE     : 2016-08-23
  CWE      : CWE-190->CWE-125
  CVSS3    : 5.9 (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
  BUGZILLA : 1369855
  FIXED_RELEASES :
   Red Hat Enterprise Linux 6: [openssl-1.0.1e-48.el6_8.3] via RHSA-2016:1940 (2016-09-27)
   Red Hat Enterprise Linux 7: [openssl-1:1.0.1e-51.el7_2.7] via RHSA-2016:1940 (2016-09-27)
  FIX_STATES :
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
[NOTICE ] rhsda: Found 1 CVEs on cmdline
[INFO   ] rhsda: Using 1 worker threads
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-6302
  SEVERITY : Moderate Impact
  DATE     : 2016-08-23
  CWE      : CWE-190->CWE-125
  CVSS     : 4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P)
  CVSS3    : 5.9 (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
  BUGZILLA : 1369855
  UPSTREAM_FIX : openssl 1.0.1u, openssl 1.0.2i
  REFERENCES :
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
The `--q-xxx` options can be combined to craft a search, listing CVEs via a single API call; add `--extract-cves` (`-x`) to perform individual CVE queries against each CVE returned by the search 

### Empty search: list CVEs by public-date

```
$ rhsecapi --loglevel info --q-empty
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve.json
[NOTICE ] rhsda: 1000 CVEs found with search query

CVE ID            PUB DATE    BUGZILLA  SEVERITY   CVSS2  CVSS3  RHSAS  PKGS
CVE-2016-9685     2016-12-01  1396941   low        2.1    3.8     0      0  
CVE-2016-9079     2016-12-01  1400376   important  6.8    7.3     0      0  
CVE-2016-5402     2016-11-30  1357559   important  8.5    8.8     1      1  
CVE-2016-8734     2016-11-29  1397403   moderate   3.5    4.4     0      0  
...
(output truncated for brevity of this README)
```

Customize how many results to see and print; add URLs. The `--q-empty` switch is no longer needed here since there are other `--q-xxx` options present.

```
$ rhsecapi --loglevel info --q-pagesize 4 --q-pagenum 3 --urls 
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve.json?per_page=4&page=3
[NOTICE ] rhsda: 4 CVEs found with search query

CVE ID                                                PUB DATE    BUGZILLA                                             SEVERITY   CVSS2  CVSS3  RHSAS  PKGS
https://access.redhat.com/security/cve/CVE-2016-8653  2016-11-25  https://bugzilla.redhat.com/show_bug.cgi?id=1398524  moderate   5.0    5.3     0      0  
https://access.redhat.com/security/cve/CVE-2016-8648  2016-11-24  https://bugzilla.redhat.com/show_bug.cgi?id=1395077  moderate   6.5    7.2     0      0  
https://access.redhat.com/security/cve/CVE-2016-6817  2016-11-22  https://bugzilla.redhat.com/show_bug.cgi?id=1397474  important  5.0    7.5     0      0  
https://access.redhat.com/security/cve/CVE-2016-9382  2016-11-22  https://bugzilla.redhat.com/show_bug.cgi?id=1392933  moderate   4.6    7.5     0      0  
```

Use `-x`/`--extract-cves` to retrieve all individual CVEs found by search.

```
$ rhsecapi --q-empty --q-pagesize 1 --extract-cves --most-fields --wrap 
[NOTICE ] rhsda: 1 CVEs found with search query
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-9685
  SEVERITY : Low Impact
  DATE     : 2016-12-01
  CWE      : CWE-772
  CVSS     : 2.1 (AV:L/AC:L/Au:N/C:P/I:N/A:N)
  CVSS3    : 3.8 (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N)
  BUGZILLA : 1396941
  FIX_STATES :
   Will not fix: Red Hat Enterprise MRG 2 [realtime-kernel]
   New: Red Hat Enterprise Linux 6 [kernel]
   Will not fix: Red Hat Enterprise Linux 7 [kernel-rt]
   Will not fix: Red Hat Enterprise Linux 7 [kernel]
```

### Find by attributes

Can combine multiple `--q-xxx` options to find desired CVEs.

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-10-01
[NOTICE ] rhsda: 6 CVEs found with search query

CVE ID         PUB DATE    BUGZILLA  SEVERITY   CVSS2  CVSS3  RHSAS  PKGS
CVE-2015-3456  2015-05-13  1218611   important  6.5            9      8  
CVE-2015-0235  2015-01-27  1183461   critical   6.8            5     10  
CVE-2014-3611  2014-10-21  1144878   important  5.5            5      5  
CVE-2014-3645  2014-10-21  1144835   moderate   4.7            4      4  
CVE-2014-3646  2014-10-21  1144825   moderate   4.7            4      4  
CVE-2014-3567  2014-10-15  1152961   moderate   4.3            3      3  
```

Other possibilities:

```
$ rhsecapi --q-[TabTab]
--q-advisory  --q-bug       --q-cwe       --q-pagenum   --q-raw       
--q-after     --q-cvss      --q-empty     --q-pagesize  --q-severity  
--q-before    --q-cvss3     --q-package   --q-product   
```

Narrowing it down ...

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-12-01 --q-severity critical --loglevel info --extract-cves --product hypervisor
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve.json?after=2014-12-01&severity=critical&package=rhev-hypervisor6
[NOTICE ] rhsda: 1 CVEs found with search query
[INFO   ] rhsda: Using 1 worker threads
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-0235.json
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 1 of 1
[NOTICE ] rhsda: Results matching spotlight-product option: 1 of 1

CVE-2015-0235
  SEVERITY : Critical Impact
  DATE     : 2015-01-27
  BUGZILLA : 1183461
  FIXED_RELEASES matching 'hypervisor' :
   RHEV Hypervisor for RHEL-6: [rhev-hypervisor6-6.6-20150123.1.el6ev] via RHSA-2015:0126 (2015-02-04)
```


### Working with IAVAs

IAVAs can be retrieved instantly ...

```
$ rhsecapi --iava 2016-A-0287 -i 2016-A-0309 --urls 
[NOTICE ] rhsda: Valid Red Hat IAVA results retrieved: 2 of 2
[NOTICE ] rhsda: Number of CVEs mapped from retrieved IAVAs: 5

2016-A-0287 (https://access.redhat.com/labs/securitydataapi/iava?number=2016-A-0287)
  TITLE    : Multiple Vulnerabilities in Oracle Enterprise Manager
  SEVERITY : CAT I
  ID       : 140611
  CVES     :
   CVE-2015-7940 (https://access.redhat.com/security/cve/CVE-2015-7940)
   CVE-2016-2107 (https://access.redhat.com/security/cve/CVE-2016-2107)
   CVE-2016-4979 (https://access.redhat.com/security/cve/CVE-2016-4979)
   CVE-2016-5604 (https://access.redhat.com/security/cve/CVE-2016-5604)

2016-A-0309 (https://access.redhat.com/labs/securitydataapi/iava?number=2016-A-0309)
  TITLE    : ISC BIND Remote Denial of Service Vulnerability
  SEVERITY : CAT I
  ID       : 140634
  CVES     :
   CVE-2016-8864 (https://access.redhat.com/security/cve/CVE-2016-8864)
```

Each of the mapped CVEs can be looked up by simply adding the `-x`/`--extract-cves` option. (For brevity, the following example also uses `--product`.)

```
$ rhsecapi --iava 2016-A-0287 -i 2016-A-0309 --urls --extract-cves --product 'linux 6'
[NOTICE ] rhsda: Valid Red Hat IAVA results retrieved: 2 of 2
[NOTICE ] rhsda: Number of CVEs mapped from retrieved IAVAs: 5
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 4 of 5
[NOTICE ] rhsda: Results matching spotlight-product option: 3 of 5

CVE-2016-8864 (https://access.redhat.com/security/cve/CVE-2016-8864)
  SEVERITY : Important Impact (https://access.redhat.com/security/updates/classification)
  DATE     : 2016-11-01
  BUGZILLA : https://bugzilla.redhat.com/show_bug.cgi?id=1389652
  FIXED_RELEASES matching 'linux 6' :
   Red Hat Enterprise Linux 6: [bind-32:9.8.2-0.47.rc1.el6_8.3] via https://access.redhat.com/errata/RHSA-2016:2141 (2016-11-02)

CVE-2016-2107 (https://access.redhat.com/security/cve/CVE-2016-2107)
  SEVERITY : Moderate Impact (https://access.redhat.com/security/updates/classification)
  DATE     : 2016-05-03
  BUGZILLA : https://bugzilla.redhat.com/show_bug.cgi?id=1331426
  FIXED_RELEASES matching 'linux 6' :
   Red Hat Enterprise Linux 6: [openssl-1.0.1e-48.el6_8.1] via https://access.redhat.com/errata/RHSA-2016:0996 (2016-05-10)
  FIX_STATES matching 'linux 6' :
   Not affected: Red Hat Enterprise Linux 6 [openssl098e]

CVE-2016-4979 (https://access.redhat.com/security/cve/CVE-2016-4979)
  SEVERITY : Moderate Impact (https://access.redhat.com/security/updates/classification)
  DATE     : 2016-07-05
  BUGZILLA : https://bugzilla.redhat.com/show_bug.cgi?id=1352476
  FIX_STATES matching 'linux 6' :
   Not affected: Red Hat Enterprise Linux 6 [httpd]
```


## Advanced: find unresolved CVEs for a specific package in a specific product

- **Question:**

  > *Are there any unresolved CVEs for the glibc package in RHEL6?*

- **Recipe:**

  1. Start with a package search (`--q-package glibc`)
  1. Extract the CVEs (`--extract-cves` or `-x`)
  1. Use spotlight-product option to narrow results (`--product 'linux 6'`)
    - Note: this option treats input as a case-insensitive extended regex and matches it against two product fields in the json data; see `--help` entry for `--product`
  1. Restrict field display to exclude the `FIXED_RELEASES` field, e.g., `-f ^releases` OR specify customized list that includes `FIX_STATES` and not `FIXED_RELEASES` (e.g., `-f severity,date,cvss,states`)
    - Note: fields parsed by `--fields`/`-f` are case-insensitive and there are multiple synonymous aliases for the RELASES & STATES fields; see `--help` entry for `--fields`

- **Example:**

  ```
  $ rhsecapi --q-package glibc --extract-cves --product 'linux 6' -f bugzilla,fix_states,severity,cvss
  [NOTICE ] rhsda: 41 CVEs found with search query
  [NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 41 of 41
  [NOTICE ] rhsda: Results matching spotlight-product option: 8 of 41

  CVE-2010-0830
    SEVERITY : Low Impact
    CVSS     : 3.7 (AV:L/AC:H/Au:N/C:P/I:P/A:P)
    BUGZILLA : 599056
    FIX_STATES matching 'linux 6' :
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2015-5277
    SEVERITY : Important Impact
    CVSS     : 3.7 (AV:L/AC:H/Au:N/C:P/I:P/A:P)
    BUGZILLA : 1262914
    FIX_STATES matching 'linux 6' :
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2016-3075
    SEVERITY : Low Impact
    CVSS     : 3.7 (AV:L/AC:H/Au:N/C:P/I:P/A:P)
    BUGZILLA : 1321866
    FIX_STATES matching 'linux 6' :
     Will not fix: Red Hat Enterprise Linux 6 [compat-glibc]
     Will not fix: Red Hat Enterprise Linux 6 [glibc]

  CVE-2014-8121
    SEVERITY : Low Impact
    CVSS     : 3.3 (AV:A/AC:L/Au:N/C:N/I:N/A:P)
    BUGZILLA : 1165192
    FIX_STATES matching 'linux 6' :
     Fix deferred: Red Hat Enterprise Linux 6 [glibc]

  CVE-2015-1473
    SEVERITY : Low Impact
    CVSS     : 2.6 (AV:L/AC:H/Au:N/C:P/I:N/A:P)
    BUGZILLA : 1209105
    FIX_STATES matching 'linux 6' :
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2015-1472
    SEVERITY : Low Impact
    CVSS     : 2.6 (AV:L/AC:H/Au:N/C:P/I:N/A:P)
    BUGZILLA : 1188235
    FIX_STATES matching 'linux 6' :
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2010-0296
    SEVERITY : Low Impact
    CVSS     : 4.3 (AV:L/AC:L/Au:S/C:P/I:P/A:P)
    BUGZILLA : 559579
    FIX_STATES matching 'linux 6' :
     Not affected: Red Hat Enterprise Linux 6 [glibc]

  CVE-2009-5029
    SEVERITY : Moderate Impact
    CVSS     : 6.5 (AV:N/AC:L/Au:S/C:P/I:P/A:P)
    BUGZILLA : 761245
    FIX_STATES matching 'linux 6' :
     Affected: Red Hat Enterprise Linux 6 [compat-glibc]
  ```


## Full help page

```
$ rhsecapi --help
usage: rhsecapi [--q-before YYYY-MM-DD] [--q-after YYYY-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT]
                [--q-product PRODUCT] [--q-package PKG] [--q-cwe CWEID]
                [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [-i YYYY-?-NNNN] [-x] [-0] [-f FIELDS | -a | -m] [-p PRODUCT]
                [-j] [-u] [-w [WIDTH]] [-c] [-l {debug,info,notice,warning}]
                [-t THREDS] [-P] [-E [DAYS]] [--dryrun] [-h] [--help]
                [CVE-YYYY-NNNN [CVE-YYYY-NNNN ...]]

Make queries against the Red Hat Security Data API
Original announcement: https://access.redhat.com/blogs/766093/posts/2387601
Docs: https://access.redhat.com/documentation/en/red-hat-security-data-api/

FIND CVES BY ATTRIBUTE:
  --q-before YYYY-MM-DD
                        Narrow down results to before a certain time period
  --q-after YYYY-MM-DD  Narrow down results to after a certain time period
  --q-bug BZID          Narrow down results by Bugzilla ID (specify one or
                        more, e.g.: '1326598,1084875')
  --q-advisory RHSA     Narrow down results by errata advisory (specify one or
                        more, e.g.: 'RHSA-2016:0614,RHSA-2016:0610')
  --q-severity IMPACT   Narrow down results by severity rating (specify one of
                        'low', 'moderate', 'important', or 'critical')
  --q-product PRODUCT   Narrow down results by product name via case-
                        insensitive regex (e.g.: 'linux 7' or 'openstack
                        platform [89]'); the API checks this against the
                        'FIXED_RELEASES' field so will only match CVEs where
                        PRODUCT matches the 'product_name' of some released
                        errata
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
                        (e.g. something new that is unknown to rhsecapi)

RETRIEVE SPECIFIC IAVAS:
  -i, --iava YYYY-?-NNNN
                        Retrieve notice details for an IAVA number; specify
                        option multiple times to retrieve multiple IAVAs at
                        once (use below --extract-cves option to lookup mapped
                        CVEs)

RETRIEVE SPECIFIC CVES:
  CVE-YYYY-NNNN         Retrieve a CVE or list of CVEs (e.g.:
                        'CVE-2016-5387'); note that case-insensitive regex-
                        matching is done -- extra characters & duplicate CVEs
                        will be discarded
  -x, --extract-cves    Extract CVEs from search query (as initiated by at
                        least one of the --q-xxx options or the --iava option)
  -0, --stdin           Extract CVEs from stdin (CVEs will be matched by case-
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
  -p, --product PRODUCT
                        Spotlight a particular PRODUCT via case-insensitive
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
  -P, --pastebin        Send output to Fedora Project Pastebin
                        (paste.fedoraproject.org) and print only URL to stdout
  -E, --pexpire [DAYS]  Set time in days after which paste will be deleted
                        (defaults to '28'; specify '0' to disable expiration;
                        DAYS defaults to '1' if option is used but DAYS is
                        omitted)
  --dryrun              Skip CVE retrieval; this option only makes sense in
                        concert with --stdin, for the purpose of quickly
                        getting a printable list of CVE ids from stdin
  -h                    Show short usage summary and exit
  --help                Show this help message and exit

VERSION:
  rhsecapi v1.0.0_rc10 last mod 2017/01/05
  See <http://github.com/ryran/rhsecapi> to report bugs or RFEs
```


## Working with backend rhsda library

The `rhsda` library does all the work of interfacing with the API. If run directly, it tries to find CVEs on stdin.

```
$ echo CVE-2016-9401 CVE-2016-9372 CVE-2016-9372 CVE-2016-9372 | python rhsda.py
[NOTICE ] rhsda: Found 2 CVEs on stdin; 2 duplicates removed
[INFO   ] rhsda: Using 2 worker threads
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-9401.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-9372.json
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 2 of 2
CVE-2016-9401
  SEVERITY : Low Impact
  DATE     : 2016-11-17
  CWE      : CWE-416
  CVSS     : 1.9 (AV:L/AC:M/Au:N/C:N/I:N/A:P)
  CVSS3    : 3.3 (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)
  BUGZILLA : 1396383
  DETAILS  : 
   ** RESERVED ** This candidate has been reserved by an organization
   or individual that will use it when announcing a new security
   problem.  When the candidate has been publicized, the details for
   this candidate will be provided.
  FIX_STATES :
   Will not fix: Red Hat Enterprise Linux 5 [bash]
   Will not fix: Red Hat Enterprise Linux 6 [bash]
   Will not fix: Red Hat Enterprise Linux 7 [bash]

CVE-2016-9372
  SEVERITY : Moderate Impact
  DATE     : 2016-11-16
  CVSS     : 4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P)
  CVSS3    : 5.9 (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
  BUGZILLA : 1396409
  DETAILS  : 
   In Wireshark 2.2.0 to 2.2.1, the Profinet I/O dissector could loop
   excessively, triggered by network traffic or a capture file. This
   was addressed in plugins/profinet/packet-pn-rtc-one.c by rejecting
   input with too many I/O objects.
  UPSTREAM_FIX : wireshark 2.2.2
  REFERENCES :
   https://www.wireshark.org/security/wnpa-sec-2016-58.html
  FIX_STATES :
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
    # Copyright 2016, 2017
    #  Ryan Sawhill Aroha <rsaw@redhat.com> and rhsecapi contributors
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
     |  cve_search_query(self, params, outFormat='list', urls=False)
     |      Perform a CVE search query.
     |      
     |      ON *OUTFORMAT*:
     |      
     |      Setting to "list" returns list of found CVE ids.
     |      Setting to "plaintext" returns str object containing new-line separated CVE ids.
     |      Setting to "json" returns list object containing original JSON.
     |      Setting to "jsonpretty" returns str object containing prettified JSON.
     |  
     |  find_cves(self, params=None, outFormat='json', before=None, after=None, bug=None, advisory=None, severity=None, product=None, package=None, cwe=None, cvss_score=None, cvss3_score=None, page=None, per_page=None)
     |      Find CVEs by recent or attributes.
     |      
     |      Provides an index to recent CVEs when no parameters are passed.
     |      Each list item is a convenience object with minimal attributes.
     |      Use parameters to narrow down results.
     |      
     |      With *outFormat* of "json", returns JSON object.
     |      With *outFormat* of "xml", returns unformatted XML as string.
     |      If *params* dict is passed, additional parameters are ignored.
     |  
     |  find_cvrfs(self, params=None, outFormat='json', before=None, after=None, bug=None, cve=None, severity=None, package=None, page=None, per_page=None)
     |      Find CVRF documents by recent or attributes.
     |      
     |      Provides an index to recent CVRF documents when no parameters are passed.
     |      Each list item is a convenience object with minimal attributes.
     |      Use parameters to narrow down results.
     |      
     |      With *outFormat* of "json", returns JSON object.
     |      With *outFormat* of "xml", returns unformatted XML as string.
     |      If *params* dict is passed, additional parameters are ignored.
     |  
     |  find_iavas(self, params=None, outFormat='json', number=None, severity=None, page=None, per_page=None)
     |      Find IAVA notices by recent or attributes.
     |      
     |      Provides an index to recent IAVA notices when no parameters are passed.
     |      Each list item is a convenience object with minimal attributes.
     |      Use parameters to narrow down results.
     |      
     |      With *outFormat* of "json", returns JSON object.
     |      With *outFormat* of "xml", returns unformatted XML as string.
     |      If *params* dict is passed, additional parameters are ignored.
     |  
     |  find_ovals(self, params=None, outFormat='json', before=None, after=None, bug=None, cve=None, severity=None, page=None, per_page=None)
     |      Find OVAL definitions by recent or attributes.
     |      
     |      Provides an index to recent OVAL definitions when no parameters are passed.
     |      Each list item is a convenience object with minimal attributes.
     |      Use parameters to narrow down results.
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
     |  get_iava(self, iava, outFormat='json')
     |      Retrieve notice details for an IAVA.
     |  
     |  get_oval(self, rhsa, outFormat='json')
     |      Retrieve OVAL details for an RHSA.
     |  
     |  mget_cves(self, cves, numThreads=0, onlyCount=False, outFormat='plaintext', urls=False, fields='ALL', wrapWidth=70, product=None, timeout=300)
     |      Use multi-threading to lookup a list of CVEs and return text output.
     |      
     |      *cves*:       A list of CVE ids or a str/file obj from which to regex CVE ids
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
     |  
     |  mget_iavas(self, iavas, numThreads=0, onlyCount=False, outFormat='plaintext', urls=False, timeout=300)
     |      Use multi-threading to lookup a list of IAVAs and return text output.
     |      
     |      *iavas*:      A list of IAVA ids
     |      *numThreads*: Number of concurrent worker threads; 0 == CPUs*2
     |      *onlyCount*:  Whether to exit after simply logging number of valid/invalid CVEs
     |      *outFormat*:  Control output format ("list", "plaintext", "json", or "jsonpretty")
     |      *urls*:       Whether to add extra URLs to certain fields
     |      *timeout*:    Total ammount of time to wait for all CVEs to be retrieved
     |      
     |      ON *OUTFORMAT*:
     |      
     |      Setting to "list" returns list object containing ONLY CVE ids.
     |      Setting to "plaintext" returns str object containing formatted output.
     |      Setting to "json" returns list object (i.e., original JSON)
     |      Setting to "jsonpretty" returns str object containing prettified JSON

FUNCTIONS
    extract_cves_from_input(obj, descriptiveNoun=None)
        Use case-insensitive regex to extract CVE ids from input object.
        
        *obj* can be a list, a file, or a string.
        
        A list of CVEs is returned.
    
    jprint(jsoninput)
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
[NOTICE ] rhsda: Found 2 CVEs on input
[INFO   ] rhsda: Using 2 worker threads
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5392.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5387.json
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 2 of 2
>>> print(txt)
CVE-2016-5392
  SEVERITY : Important Impact
  DATE     : 2016-07-14
  CWE      : CWE-20
  CVSS     : 6.8 (AV:N/AC:L/Au:S/C:C/I:N/A:N)
  CVSS3    : 6.5 (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
  BUGZILLA : 1356195
  ACKNOWLEDGEMENT :  
   This issue was discovered by Yanping Zhang (Red Hat).
  DETAILS  : 
   The API server in Kubernetes, as used in Red Hat OpenShift
   Enterprise 3.2, in a multi tenant environment allows remote
   authenticated users with knowledge of other project names to obtain
   sensitive project and user information via vectors related to the
   watch-cache list.  The Kubernetes API server contains a watch cache
   that speeds up performance. Due to an input validation error
   OpenShift Enterprise may return data for other users and projects
   when queried by a user. An attacker with knowledge of other project
   names could use this vulnerability to view their information.
  FIXED_RELEASES :
   Red Hat OpenShift Enterprise 3.2: [atomic-openshift-3.2.1.7-1.git.0.2702170.el7] via RHSA-2016:1427 (2016-07-14)
  FIX_STATES :
   Affected: Red Hat OpenShift Enterprise 3 [Security]

CVE-2016-5387
  SEVERITY : Important Impact
  DATE     : 2016-07-18
  IAVA     : 2016-B-0160
  CWE      : CWE-20
  CVSS     : 5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)
  CVSS3    : 5.0 (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N)
  BUGZILLA : 1353755
  ACKNOWLEDGEMENT :  
   Red Hat would like to thank Scott Geary (VendHQ) for reporting this
   issue.
  DETAILS  : 
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
  UPSTREAM_FIX : httpd 2.4.24, httpd 2.2.32
  REFERENCES :
   https://access.redhat.com/security/vulnerabilities/httpoxy
   https://httpoxy.org/
   https://www.apache.org/security/asf-httpoxy-response.txt
  FIXED_RELEASES :
   Red Hat Enterprise Linux 5: [httpd-2.2.3-92.el5_11] via RHSA-2016:1421 (2016-07-18)
   Red Hat Enterprise Linux 6: [httpd-2.2.15-54.el6_8] via RHSA-2016:1421 (2016-07-18)
   Red Hat Enterprise Linux 7: [httpd-2.4.6-40.el7_2.4] via RHSA-2016:1422 (2016-07-18)
   Red Hat JBoss Core Services 1: via RHSA-2016:1625 (2016-08-17)
   Red Hat JBoss Core Services on RHEL 6 Server: [jbcs-httpd24-httpd-2.4.6-77.SP1.jbcs.el6] via RHSA-2016:1851 (2016-09-12)
   Red Hat JBoss Core Services on RHEL 7 Server: [jbcs-httpd24-httpd-2.4.6-77.SP1.jbcs.el7] via RHSA-2016:1851 (2016-09-12)
   Red Hat JBoss Enterprise Web Server 2 for RHEL 6 Server: [httpd-2.2.26-54.ep6.el6] via RHSA-2016:1649 (2016-08-22)
   Red Hat JBoss Enterprise Web Server 2 for RHEL 7 Server: [httpd22-2.2.26-56.ep6.el7] via RHSA-2016:1648 (2016-08-22)
   Red Hat JBoss Web Server 2.1: via RHSA-2016:1650 (2016-08-22)
   Red Hat JBoss Web Server 3.0: via RHSA-2016:1624 (2016-08-17)
   Red Hat JBoss Web Server 3.0 for RHEL 6: via RHSA-2016:1636 (2016-08-18)
   Red Hat JBoss Web Server 3.0 for RHEL 7: via RHSA-2016:1635 (2016-08-18)
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 6): [httpd24-httpd-2.4.18-11.el6] via RHSA-2016:1420 (2016-07-18)
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 7): [httpd24-httpd-2.4.18-11.el7] via RHSA-2016:1420 (2016-07-18)
  FIX_STATES :
   Affected: Red Hat JBoss EAP 6 [httpd22]
   Not affected: Red Hat JBoss EAP 7 [httpd22]
   Will not fix: Red Hat JBoss EWS 1 [httpd]
```

The `mget_cves()` method's `cves=` argument (the 1st kwarg) regex-finds CVEs in an input string:

```
>>> s = "Hello thar we need CVE-2016-5387 fixed as well as CVE-2016-5392(worst).\nAnd not to mention CVE-2016-2379,CVE-2016-1000219please."
>>> a = rhsda.ApiClient('info')
>>> json = a.mget_cves(s, outFormat='json')
[NOTICE ] rhsda: Found 4 CVEs on input
[INFO   ] rhsda: Using 4 worker threads
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5392.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-1000219.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5387.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-2379.json
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 4 of 4
```

... or a file:

```
>>> a = rhsda.ApiClient()
>>> with open('scan-results.csv') as f:
...     txt = a.mget_cves(f)
... 
[NOTICE ] rhsda: Found 150 CVEs on input; 698 duplicates removed
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 148 of 150
```

Also of course a list is fine:

```
>>> L = ['CVE-2016-5387', 'CVE-2016-5392', 'CVE-2016-2379', 'CVE-2016-5773']
>>> print(a.mget_cves(L, fields='BASE', product='web.server.3'))
[INFO   ] rhsda: Using 4 worker threads
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5387.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5392.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-2379.json
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5773.json
[INFO   ] rhsda: Hiding CVE-2016-2379 due to negative product match
[INFO   ] rhsda: Hiding CVE-2016-5773 due to negative product match
[INFO   ] rhsda: Hiding CVE-2016-5392 due to negative product match
[NOTICE ] rhsda: Valid Red Hat CVE results retrieved: 4 of 4
[NOTICE ] rhsda: Results matching spotlight-product option: 1 of 4
CVE-2016-5387
  SEVERITY : Important Impact
  DATE     : 2016-07-18
  BUGZILLA : 1353755
  FIXED_RELEASES matching 'web.server.3' :
   Red Hat JBoss Web Server 3.0: via RHSA-2016:1624 (2016-08-17)
   Red Hat JBoss Web Server 3.0 for RHEL 6: via RHSA-2016:1636 (2016-08-18)
   Red Hat JBoss Web Server 3.0 for RHEL 7: via RHSA-2016:1635 (2016-08-18)
```

There's also a convenience `cve_search_query()` method.

```
>>> txt = a.cve_search_query({'after':'2015-01-01', 'before':'2015-02-01', 'per_page':5}, outFormat='plaintext')
[INFO   ] rhsda: Getting https://access.redhat.com/labs/securitydataapi/cve.json?per_page=5&after=2015-01-01&before=2015-02-01
[NOTICE ] rhsda: 5 CVEs found with search query
>>> print(txt)
CVE ID         PUB DATE    BUGZILLA  SEVERITY  CVSS2  CVSS3  RHSAS  PKGS
CVE-2014-0141  2015-01-29  1187466   moderate  4.3            0      0  
CVE-2015-1563  2015-01-29  1187153   low       2.1            0      0  
CVE-2015-8779  2015-01-29  1300312   moderate  5.1            0      0  
CVE-2014-9749  2015-01-28  1186768   moderate  4.0            0      0  
CVE-2015-0210  2015-01-28  1178921   moderate  5.4            0      0  
```
