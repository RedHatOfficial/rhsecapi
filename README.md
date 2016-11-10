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
- [Full help page](#full-help-page)
- [Testing from python shell](#testing-from-python-shell)

## Simple CVE retrieval

Specify as many CVEs on cmdline as needed; certain details are printed to stderr -- e.g., in the following, the first 4 lines of output were sent to stderr

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642
rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-4642.json
Valid Red Hat CVE results retrieved: 3 of 4
Invalid CVE queries: 1 of 4

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

A `--spotlight` option allows spotlighting a particular product via a case-insenstive regex, e.g., here's the same exact command above spotlighting EUS products:

```
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642 --spotlight eus
rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-4642.json
Valid Red Hat CVE results retrieved: 3 of 4
Results matching spotlight-product option: 2 of 4
Invalid CVE queries: 1 of 4

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
$ rhsecapi CVE-2013-4113 CVE-2014-3669 CVE-2004-0230 CVE-2015-4642 --spotlight eus --urls 2>/dev/null
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
rhsecapi: Found 6 CVEs in stdin; 0 duplicates removed

rhsecapi: Unable to auto-detect terminal width due to stdin redirection; setting WIDTH to 70
Valid Red Hat CVE results retrieved: 6 of 6
```

Second example: piping in file(s) with `cat|` or file redirection (`< somefile`)

```
$ cat scan-results.csv | rhsecapi -0 -c
rhsecapi: Found 150 CVEs in stdin; 698 duplicates removed

rhsecapi: Unable to auto-detect terminal width due to stdin redirection; setting WIDTH to 70
rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-3197.json
rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-4642.json
Valid Red Hat CVE results retrieved: 148 of 150
Invalid CVE queries: 2 of 150
```

The CVE retrieval process is multi-threaded; with CPUcount < 4, it defaults to 4 threads; with CPUcount > 4, it defaults to `CPUcount * 2` 

```
$ grep processor /proc/cpuinfo | wc -l
4

$ rhsecapi --help | grep -A1 threads
  -t, --threads THREDS  Set number of concurrent worker threads to allow when
                        making CVE queries (default on this system: 8)

$ time rhsecapi --q-empty --q-pagesize 48 --extract-search >/dev/null
CVEs found: 48

Valid Red Hat CVE results retrieved: 48 of 48

real	0m3.197s
user	0m0.613s
sys	0m0.077s
```

## Installation

- **Option 1: Download python script directly from github and run it**
  1. Download very latest (potentially bleeding-edge & broken) version: `curl -LO https://raw.githubusercontent.com/ryran/rhsecapi/master/rhsecapi.py`
  1. Add execute bit: `chmod +x rhsecapi.py`
  1. Execute: `./rhsecapi.py`

- **Option 2 for RHEL6, RHEL7, Fedora: Install rsaw's yum repo and then rhsecapi rpm**
  1. If you don't already have rsaw's yum repo due to xsos or upvm or something else, set it up with the following command: `yum install http://people.redhat.com/rsawhill/rpms/latest-rsawaroha-release.rpm`
  1. Install rhsecapi: `yum install rhsecapi`
  1. Execute: `rhsecapi`
  
## Abbreviated usage

```
$ rhsecapi -h
usage: rhsecapi [--q-before YEAR-MM-DD] [--q-after YEAR-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT] [--q-package PKG]
                [--q-cwe CWEID] [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [--q-iava IAVA] [-s] [-0] [-f FIELDS | -a | -m]
                [--spotlight PRODUCT] [-j] [-u] [-w [WIDTH]] [-c] [-v]
                [-t THREDS] [-p] [-E [DAYS]] [-h] [--help]
                [CVE [CVE ...]]

Run rhsecapi --help for full help page

VERSION:
  rhsecapi v0.9.0 last mod 2016/11/07
  See <http://github.com/ryran/rhsecapi> to report bugs or RFEs
```

## BASH intelligent tab-completion

```
$ rhsecapi --
--all-fields      --json            --q-before        --q-iava          --spotlight
--count           --most-fields     --q-bug           --q-package       --threads
--extract-search  --pastebin        --q-cvss          --q-pagenum       --urls
--extract-stdin   --pexpire         --q-cvss3         --q-pagesize      --verbose
--fields          --q-advisory      --q-cwe           --q-raw           --wrap
--help            --q-after         --q-empty         --q-severity      
```

## Field display

Add some fields to the defaults with `--fields +field[,field]...` and note that arguments to `--fields` are handled in a case-insensitive way

```
$ rhsecapi CVE-2016-6302 -v --fields +CWE,cvss3
DEBUG THREADS: '1'
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json' ...
Valid Red Hat CVE results retrieved: 1 of 1
DEBUG FIELDS: 'threat_severity,public_date,bugzilla,affected_release,package_state,cwe,cvss3'

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

Remove some fields from the defaults with `--fields ^field[,field]...`

```
$ rhsecapi CVE-2016-6302 -vf ^FIXED_reLEASES,fIx_sTaTes
DEBUG THREADS: '1'
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json' ...
Valid Red Hat CVE results retrieved: 1 of 1
DEBUG FIELDS: 'threat_severity,public_date,bugzilla'

CVE-2016-6302
  SEVERITY: Moderate Impact
  DATE:     2016-08-23
  BUGZILLA: 1369855
```

Note that there are also two presets: `--all-fields` and `--most-fields`

```
$ rhsecapi CVE-2016-6302 -v --most-fields 2>&1 | grep FIELDS
DEBUG FIELDS: 'threat_severity,public_date,iava,cwe,cvss,cvss3,bugzilla,upstream_fix,affected_release,package_state'

$ rhsecapi CVE-2016-6302 -v --all-fields 2>&1 | grep FIELDS
DEBUG FIELDS: 'threat_severity,public_date,iava,cwe,cvss,cvss3,bugzilla,acknowledgement,details,statement,mitigation,upstream_fix,references,affected_release,package_state'
```

## Find CVEs
The `--q-xxx` options can be combined to craft a search, listing CVEs via a single API call; add `--extract-search` (`-s`) to perform individual CVE queries against each CVE returned by the search 

### Empty search: list CVEs by public-date

```
$ rhsecapi --verbose --q-empty
Getting 'https://access.redhat.com/labs/securitydataapi/cve.json' ...
CVEs found: 1000

CVE-2016-8634
CVE-2016-7035
CVE-2016-8615
CVE-2016-8625
CVE-2016-8619
CVE-2016-8624
CVE-2016-8623
... (output truncated for brevity of this README)
```

```
$ rhsecapi --verbose --q-empty --q-pagesize 5 --q-pagenum 3
Getting 'https://access.redhat.com/labs/securitydataapi/cve.json?per_page=5&page=3' ...
CVEs found: 5

CVE-2016-8617
CVE-2016-8618
CVE-2016-8621
CVE-2016-8864
CVE-2016-9013
```

```
$ rhsecapi --q-empty --q-pagesize 1 --extract-search --all-fields --wrap 
CVEs found: 1

Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-8632
  SEVERITY: Moderate Impact
  DATE:     2016-11-07
  CWE:      119
  CVSS:     6.8 (AV:L/AC:L/Au:S/C:C/I:C/A:C)
  BUGZILLA: 1390832
  ACKNOWLEDGEMENT:  
   Red Hat would like to thank Qian Zhang from MarvelTeam of Qihoo 360
   for reporting this issue.
  DETAILS:  
   ** RESERVED ** This candidate has been reserved by an organization
   or individual that will use it when announcing a new security
   problem.  When the candidate has been publicized, the details for
   this candidate will be provided.  A flaw was found in the TIPC
   networking subsystem which could allow for memory corruption and
   possible privilege escalation.  The flaw involves a system with an
   unusually low MTU (60) on networking devices configured as bearers
   for the TIPC protocol. An attacker could create a packet which will
   overwrite memory outside of allocated space and allow for privilege
   escalation.
  STATEMENT:  
   This issue is rated as important.  The affected code is not enabled
   on Red Hat Enterprise Linux 6 and 7 or MRG-2 kernels.  The commit
   introducing the comment was not included in Red Hat Enterprise
   Linux 5.
  FIX_STATES:
   Not affected: Red Hat Enterprise Linux 5 [kernel]
   Not affected: Red Hat Enterprise Linux 6 [kernel]
   Not affected: Red Hat Enterprise Linux 7 [kernel]
```

### Find by attributes

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-10-01
CVEs found: 6

CVE-2015-3456
CVE-2015-0235
CVE-2014-3611
CVE-2014-3645
CVE-2014-3646
CVE-2014-3567
```

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-10-01 --count
CVEs found: 6
```

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-12-01 --q-severity critical --json
CVEs found: 1

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
$ rhsecapi -v --q-package rhev-hypervisor6 --q-after 2014-12-01 --q-severity critical --extract-search --spotlight hypervisor
Getting 'https://access.redhat.com/labs/securitydataapi/cve.json?after=2014-12-01&severity=critical&package=rhev-hypervisor6' ...
CVEs found: 1

DEBUG THREADS: '1'
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-0235.json' ...
Valid Red Hat CVE results retrieved: 1 of 1
DEBUG FIELDS: 'threat_severity,public_date,bugzilla,affected_release,package_state'

CVE-2015-0235
  SEVERITY: Critical Impact
  DATE:     2015-01-27
  BUGZILLA: 1183461
  FIXED_RELEASES matching 'hypervisor':
   RHEV Hypervisor for RHEL-6 [rhev-hypervisor6-6.6-20150123.1.el6ev]: RHSA-2015:0126
```



### Find CVEs by IAVA

```
$ rhsecapi --verbose --q-iava invalid
Getting 'https://access.redhat.com/labs/iavmmapper/api/iava/' ...
rhsecapi: Login error; unable to get IAVA info

IAVA->CVE mapping data is not provided by the public RH Security Data API.
Instead, this uses the IAVM Mapper App (access.redhat.com/labs/iavmmapper).

Access to this data requires RH Customer Portal credentials be provided.
Create a ~/.netrc with the following contents:

machine access.redhat.com
  login YOUR-CUSTOMER-PORTAL-LOGIN
  password YOUR_PASSWORD_HERE

For help, open an issue at http://github.com/ryran/rhsecapi
Or post a comment at https://access.redhat.com/discussions/2713931

$ vim ~/.netrc

$ rhsecapi --verbose --q-iava invalid 
Getting 'https://access.redhat.com/labs/iavmmapper/api/iava/' ...
rhsecapi: IAVM Mapper (https://access.redhat.com/labs/iavmmapper) has no knowledge of 'invalid'

For help, open an issue at http://github.com/ryran/rhsecapi
Or post a comment at https://access.redhat.com/discussions/2713931
```

```
$ rhsecapi --q-iava 2016-A-0287 
CVEs found: 4

CVE-2015-7940
CVE-2016-2107
CVE-2016-4979
CVE-2016-5604
```

```
$ rhsecapi --q-iava 2016-A-0287 --json 
CVEs found: 4

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
$ rhsecapi --q-iava 2016-A-0287 --extract-search --count 
CVEs found: 4
rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5604.json
Valid Red Hat CVE results retrieved: 3 of 4
Invalid CVE queries: 1 of 4
```

```
$ rhsecapi --q-iava 2016-A-0287 --extract-search --spotlight linux.6
CVEs found: 4

rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5604.json
Valid Red Hat CVE results retrieved: 3 of 4
Results matching spotlight-product option: 2 of 4
Invalid CVE queries: 1 of 4

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

## Full help page

```
$ rhsecapi --help
usage: rhsecapi [--q-before YEAR-MM-DD] [--q-after YEAR-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT] [--q-package PKG]
                [--q-cwe CWEID] [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [--q-iava IAVA] [-s] [-0] [-f FIELDS | -a | -m]
                [--spotlight PRODUCT] [-j] [-u] [-w [WIDTH]] [-c] [-v]
                [-t THREDS] [-p] [-E [DAYS]] [-h] [--help]
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
                        caret (^) to remove fields from the default (e.g., '-f
                        ^bugzilla,severity')
  -a, --all-fields      Display all supported fields (currently:
                        threat_severity, public_date, iava, cwe, cvss, cvss3,
                        bugzilla, acknowledgement, details, statement,
                        mitigation, upstream_fix, references,
                        affected_release, package_state)
  -m, --most-fields     Display all fields mentioned above except the heavy-
                        text ones -- (excludes: acknowledgement, details,
                        statement, mitigation, references)
  --spotlight PRODUCT   Spotlight a particular PRODUCT via case-insensitive
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
                        details, statement, mitigation) in non-json output
                        (default: wrapping WIDTH equivalent to TERMWIDTH-2
                        unless using '--pastebin' where default WIDTH is
                        '168'; specify '0' to disable wrapping; WIDTH defaults
                        to '70' if option is used but WIDTH is omitted)
  -c, --count           Exit after printing CVE counts
  -v, --verbose         Print API urls & other debugging info to stderr
  -t, --threads THREDS  Set number of concurrent worker threads to allow when
                        making CVE queries (default on this system: 8)
  -p, --pastebin        Send output to Fedora Project Pastebin
                        (paste.fedoraproject.org) and print only URL to stdout
  -E, --pexpire [DAYS]  Set time in days after which paste will be deleted
                        (defaults to '28'; specify '0' to disable expiration;
                        DAYS defaults to '1' if option is used but DAYS is
                        omitted)
  -h                    Show short usage summary and exit
  --help                Show this help message and exit

VERSION:
  rhsecapi v0.9.0 last mod 2016/11/07
  See <http://github.com/ryran/rhsecapi> to report bugs or RFEs
```

## Testing from python shell

```
$ python
>>> import rhsecapi as r
>>> help(r.a)
Help on instance of RedHatSecDataApiClient in module rhsecapi:

class RedHatSecDataApiClient
 |  Portable object to interface with the Red Hat Security Data API.
 |  
 |  https://access.redhat.com/documentation/en/red-hat-security-data-api/
 |  
 |  Requires:
 |    requests
 |    sys
 |  
 |  Methods defined here:
 |  
 |  __init__(self, progressToStderr=False, apiurl='https://access.redhat.com/labs/securitydataapi')
 |  
 |  get_cve(self, cve)
 |  
 |  get_cvrf(self, rhsa)
 |  
 |  get_cvrf_oval(self, rhsa)
 |  
 |  get_oval(self, rhsa)
 |  
 |  search_cve(self, params=None)
 |  
 |  search_cvrf(self, params=None)
 |  
 |  search_oval(self, params=None)
(END)
>>> r.a.search_oval("cve=CVE-2016-5387")
Getting 'https://access.redhat.com/labs/securitydataapi/oval.json?cve=CVE-2016-5387' ...
('https://access.redhat.com/labs/securitydataapi/oval.json?cve=CVE-2016-5387', [{u'severity': u'important', u'bugzillas': [u'1353755'], u'resource_url': u'https://access.redhat.com/labs/securitydataapi/oval/RHSA-2016:1421.json', u'released_on': u'2016-07-18T04:00:00+00:00', u'RHSA': u'RHSA-2016:1421', u'CVEs': [u'CVE-2016-5387']}, {u'severity': u'important', u'bugzillas': [u'1347648', u'1353269', u'1353755'], u'resource_url': u'https://access.redhat.com/labs/securitydataapi/oval/RHSA-2016:1422.json', u'released_on': u'2016-07-18T04:00:00+00:00', u'RHSA': u'RHSA-2016:1422', u'CVEs': [u'CVE-2016-5387']}])
>>> r.jprint(r.a.search_oval("cve=CVE-2016-5387"))
Getting 'https://access.redhat.com/labs/securitydataapi/oval.json?cve=CVE-2016-5387' ...
[
  "https://access.redhat.com/labs/securitydataapi/oval.json?cve=CVE-2016-5387", 
  [
    {
      "CVEs": [
        "CVE-2016-5387"
      ], 
      "RHSA": "RHSA-2016:1421", 
      "bugzillas": [
        "1353755"
      ], 
      "released_on": "2016-07-18T04:00:00+00:00", 
      "resource_url": "https://access.redhat.com/labs/securitydataapi/oval/RHSA-2016:1421.json", 
      "severity": "important"
    }, 
    {
      "CVEs": [
        "CVE-2016-5387"
      ], 
      "RHSA": "RHSA-2016:1422", 
      "bugzillas": [
        "1347648", 
        "1353269", 
        "1353755"
      ], 
      "released_on": "2016-07-18T04:00:00+00:00", 
      "resource_url": "https://access.redhat.com/labs/securitydataapi/oval/RHSA-2016:1422.json", 
      "severity": "important"
    }
  ]
]
```
