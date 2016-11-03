# redhat-security-data-api

`rhsecapi` makes it easy to interface with the [Red Hat Security Data API](https://access.redhat.com/documentation/en/red-hat-security-data-api/).

Feedback/issues and pull requests are welcome. Would particularly like feedback on the name `rhsecapi` as well as the options (e.g., `--q-xxx`). If you don't have a GitHub account but do have a Red Hat Portal login, go here: [New cmdline tool: redhat-security-data-api - rhsecapi](https://access.redhat.com/discussions/2713931).

## Jump to ...
- [Abbreviated usage](#abbreviated-usage)
- [Simple CVE retrieval](#simple-cve-retrieval)
- [BASH intelligent tab-completion](#bash-intelligent-tab-completion)
- [Field display](#field-display)
- [Find CVEs](#find-cves)
  - [Empty search: list CVEs by public-date](#empty-search-list-cves-by-public-date)
  - [Find CVEs by attributes](#find-cves-by-attributes)
  - [Find CVEs by IAVA](#find-cves-by-iava)
- [Full help page](#full-help-page)
- [Testing from python shell](#testing-from-python-shell)

## Abbreviated usage

```
$ rhsecapi -h
usage: rhsecapi [--q-before YEAR-MM-DD] [--q-after YEAR-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT] [--q-package PKG]
                [--q-cwe CWEID] [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [--q-iava IAVA] [-x] [-f FIELDS | -a | -m] [-j] [-u]
                [-w [WIDTH]] [-c] [-v] [-t THREDS] [-p] [-E [DAYS]] [-h]
                [--help]
                [CVE [CVE ...]]

Run rhsecapi --help for full help page

VERSION:
  rhsecapi v0.7.0 last mod 2016/11/03
  See <http://github.com/ryran/redhat-security-data-api> to report bugs or RFEs
```

## Simple CVE retrieval

```
$ rhsecapi CVE-2004-0230 CVE-2015-4642 CVE-2010-5298
rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-4642.json
Valid Red Hat CVE results retrieved: 2 of 3
Invalid CVE queries: 1 of 3

CVE-2004-0230
  BUGZILLA:  No Bugzilla data
   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy

CVE-2015-4642
 Not present in Red Hat CVE database
 Try https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4642

CVE-2010-5298
  IMPACT:  Moderate
  DATE:  2014-04-08
  BUGZILLA:  1087195
  AFFECTED_RELEASE (ERRATA)
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-16.el6_5.14]: RHSA-2014:0625
   Red Hat Enterprise Linux 7 [openssl-1:1.0.1e-34.el7_0.3]: RHSA-2014:0679
   Red Hat Storage Server 2.1 [openssl-1.0.1e-16.el6_5.14]: RHSA-2014:0628
  PACKAGE_STATE
   Not affected: Red Hat JBoss EAP 5 [openssl]
   Not affected: Red Hat JBoss EAP 6 [openssl]
   Not affected: Red Hat JBoss EWS 1 [openssl]
   Not affected: Red Hat JBoss EWS 2 [openssl]
   Not affected: RHEV-M for Servers [mingw-virt-viewer]
   Not affected: Red Hat Enterprise Linux 5 [openssl097a]
   Not affected: Red Hat Enterprise Linux 5 [openssl]
   Not affected: Red Hat Enterprise Linux 6 [guest-images]
   Not affected: Red Hat Enterprise Linux 6 [openssl098e]
   Not affected: Red Hat Enterprise Linux 7 [openssl098e]
```

```
$ rhsecapi CVE-2004-0230 CVE-2015-4642 CVE-2010-5298 --urls 2>/dev/null
CVE-2004-0230 (https://access.redhat.com/security/cve/CVE-2004-0230)
  BUGZILLA:  No Bugzilla data
   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy

CVE-2015-4642
 Not present in Red Hat CVE database
 Try https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4642

CVE-2010-5298 (https://access.redhat.com/security/cve/CVE-2010-5298)
  IMPACT:  Moderate (https://access.redhat.com/security/updates/classification)
  DATE:  2014-04-08
  BUGZILLA:  https://bugzilla.redhat.com/show_bug.cgi?id=1087195
  AFFECTED_RELEASE (ERRATA):
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-16.el6_5.14]: https://access.redhat.com/errata/RHSA-2014:0625
   Red Hat Enterprise Linux 7 [openssl-1:1.0.1e-34.el7_0.3]: https://access.redhat.com/errata/RHSA-2014:0679
   Red Hat Storage Server 2.1 [openssl-1.0.1e-16.el6_5.14]: https://access.redhat.com/errata/RHSA-2014:0628
  PACKAGE_STATE:
   Not affected: Red Hat JBoss EAP 5 [openssl]
   Not affected: Red Hat JBoss EAP 6 [openssl]
   Not affected: Red Hat JBoss EWS 1 [openssl]
   Not affected: Red Hat JBoss EWS 2 [openssl]
   Not affected: RHEV-M for Servers [mingw-virt-viewer]
   Not affected: Red Hat Enterprise Linux 5 [openssl097a]
   Not affected: Red Hat Enterprise Linux 5 [openssl]
   Not affected: Red Hat Enterprise Linux 6 [guest-images]
   Not affected: Red Hat Enterprise Linux 6 [openssl098e]
   Not affected: Red Hat Enterprise Linux 7 [openssl098e]
```

Note that the CVE retrieval process is multi-threaded

```
$ rhsecapi --help | grep -A1 threads
  -t, --threads THREDS  Set number of concurrent worker threads to allow when
                        making CVE queries (default on this system: 5)

$ time rhsecapi --q-empty --q-pagesize 10 --extract-search --verbose >/dev/null
Getting 'https://access.redhat.com/labs/securitydataapi/cve.json?per_page=10' ...
CVEs found: 10

DEBUG FIELDS: 'threat_severity,public_date,bugzilla,affected_release,package_state'
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8634.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-7035.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8615.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8625.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8619.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8624.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8623.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8622.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8620.json' ...
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-8616.json' ...
Valid Red Hat CVE results retrieved: 10 of 10

real	0m2.502s
user	0m0.242s
sys	0m0.038s
```

## BASH intelligent tab-completion

```
$ rhsecapi --
--all-fields      --most-fields     --q-bug           --q-package       --urls
--count           --pastebin        --q-cvss          --q-pagenum       --verbose
--extract-search  --pexpire         --q-cvss3         --q-pagesize      --wrap
--fields          --q-advisory      --q-cwe           --q-raw           
--help            --q-after         --q-empty         --q-severity      
--json            --q-before        --q-iava          --threads         
```

## Field display

Add some fields to the defaults with `--fields +field[,field]...`

```
$ rhsecapi CVE-2016-6302 -v --fields +cwe,cvss3
DEBUG FIELDS: 'threat_severity,public_date,bugzilla,affected_release,package_state,cwe,cvss3'
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json' ...
Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-6302
  IMPACT:  Moderate
  DATE:  2016-08-23
  CWE:  CWE-190->CWE-125
  CVSS3:  5.9 (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)
  BUGZILLA:  1369855
  AFFECTED_RELEASE (ERRATA):
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-48.el6_8.3]: RHSA-2016:1940
   Red Hat Enterprise Linux 7 [openssl-1:1.0.1e-51.el7_2.7]: RHSA-2016:1940
  PACKAGE_STATE:
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
$ rhsecapi CVE-2016-6302 -vf ^package_state,affected_release
DEBUG FIELDS: 'threat_severity,public_date,bugzilla'
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-6302.json' ...
Valid Red Hat CVE results retrieved: 1 of 1

CVE-2016-6302
  IMPACT:  Moderate
  DATE:  2016-08-23
  BUGZILLA:  1369855
```

Note that there are also two presets: `--all-fields` and `--most-fields`

```
$ rhsecapi CVE-2016-6302 -v --most-fields 2>&1 | grep DEBUG
DEBUG FIELDS: 'threat_severity,public_date,iava,cwe,cvss,cvss3,bugzilla,upstream_fix,affected_release,package_state'

$ rhsecapi CVE-2016-6302 -v --all-fields 2>&1 | grep DEBUG
DEBUG FIELDS: 'threat_severity,public_date,iava,cwe,cvss,cvss3,bugzilla,acknowledgement,details,statement,mitigation,upstream_fix,references,affected_release,package_state'
```

## Find CVEs
The `--q-xxx` options can be combined to craft a search, listing CVEs via a single API call; add `--extract-search` (`-x`) to perform individual CVE queries against each CVE returned by the search 

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

CVE-2016-8634
  IMPACT:  Moderate
  DATE:  2016-11-03
  CWE:  CWE-79
  CVSS:  4.9 (AV:N/AC:M/Au:S/C:P/I:P/A:N)
  CVSS3:  6.1 (CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)
  BUGZILLA:  1391520
  ACKNOWLEDGEMENT:  
   This issue was discovered by Sanket Jagtap (Red Hat).
  DETAILS:  
   ** RESERVED ** This candidate has been reserved by an organization
   or individual that will use it when announcing a new security
   problem.  When the candidate has been publicized, the details for
   this candidate will be provided.
  PACKAGE_STATE:
   Affected: Red Hat Satellite 6 [foreman]
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
$ rhsecapi -v --q-package rhev-hypervisor6 --q-after 2014-12-01 --q-severity critical --extract-search 
Getting 'https://access.redhat.com/labs/securitydataapi/cve.json?after=2014-12-01&severity=critical&package=rhev-hypervisor6' ...
CVEs found: 1

DEBUG FIELDS: 'threat_severity,public_date,bugzilla,affected_release,package_state'
Getting 'https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-0235.json' ...
Valid Red Hat CVE results retrieved: 1 of 1

CVE-2015-0235
  IMPACT:  Critical
  DATE:  2015-01-27
  BUGZILLA:  1183461
  AFFECTED_RELEASE (ERRATA):
   Red Hat Enterprise Linux 5 [glibc-2.5-123.el5_11.1]: RHSA-2015:0090
   Red Hat Enterprise Linux 6 [glibc-2.12-1.149.el6_6.5]: RHSA-2015:0092
   RHEV Hypervisor for RHEL-6 [rhev-hypervisor6-6.6-20150123.1.el6ev]: RHSA-2015:0126
   Red Hat Enterprise Linux 7 [glibc-2.17-55.el7_0.5]: RHSA-2015:0092
   Red Hat Enterprise Linux Extended Lifecycle Support 4 [glibc-2.3.4-2.57.el4.2]: RHSA-2015:0101
   Red Hat Enterprise Linux EUS (v. 5.9 server) [glibc-2.5-107.el5_9.8]: RHSA-2015:0099
   Red Hat Enterprise Linux Extended Update Support 6.4 [glibc-2.12-1.107.el6_4.7]: RHSA-2015:0099
   Red Hat Enterprise Linux Extended Update Support 6.5 [glibc-2.12-1.132.el6_5.5]: RHSA-2015:0099
   Red Hat Enterprise Linux Long Life (v. 5.6 server) [glibc-2.5-58.el5_6.6]: RHSA-2015:0099
   Red Hat Enterprise Linux Advanced Update Support 6.2 [glibc-2.12-1.47.el6_2.15]: RHSA-2015:0099
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

For help, open an issue at http://github.com/ryran/redhat-security-data-api
Or post a comment at https://access.redhat.com/discussions/2713931

$ vim ~/.netrc

$ rhsecapi --verbose --q-iava invalid 
Getting 'https://access.redhat.com/labs/iavmmapper/api/iava/' ...
rhsecapi: IAVM Mapper (https://access.redhat.com/labs/iavmmapper) has no knowledge of 'invalid'

For help, open an issue at http://github.com/ryran/redhat-security-data-api
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
$ rhsecapi --q-iava 2016-A-0287 --extract-search 
CVEs found: 4

rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5604.json
Valid Red Hat CVE results retrieved: 3 of 4
Invalid CVE queries: 1 of 4

CVE-2015-7940
  IMPACT:  Moderate
  DATE:  2015-09-14
  BUGZILLA:  1276272
  AFFECTED_RELEASE (ERRATA):
   Red Hat Jboss A-MQ 6.3: RHSA-2016:2036
   Red Hat Jboss Fuse 6.3: RHSA-2016:2035
  PACKAGE_STATE:
   Will not fix: Red Hat Satellite 6 [bouncycastle]
   Will not fix: Red Hat Subscription Asset Manager 1 [bouncycastle]

CVE-2016-2107
  IMPACT:  Moderate
  DATE:  2016-05-03
  BUGZILLA:  1331426
  AFFECTED_RELEASE (ERRATA):
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-48.el6_8.1]: RHSA-2016:0996
   Red Hat Enterprise Linux 7 [openssl-1:1.0.1e-51.el7_2.5]: RHSA-2016:0722
   Red Hat Enterprise Linux Extended Update Support 6.7 [openssl-1.0.1e-42.el6_7.5]: RHSA-2016:2073
  PACKAGE_STATE:
   Not affected: Red Hat JBoss EAP 5 [openssl]
   Not affected: Red Hat JBoss EAP 6 [openssl]
   Not affected: Red Hat JBoss EWS 2 [openssl]
   Affected: Red Hat JBoss Web Server 3.0 [openssl]
   Not affected: Red Hat Enterprise Linux 4 [openssl096b]
   Not affected: Red Hat Enterprise Linux 4 [openssl]
   Not affected: Red Hat Enterprise Linux 5 [openssl097a]
   Not affected: Red Hat Enterprise Linux 5 [openssl]
   Not affected: Red Hat Enterprise Linux 6 [openssl098e]
   Not affected: Red Hat Enterprise Linux 7 [openssl098e]

CVE-2016-4979
  IMPACT:  Moderate
  DATE:  2016-07-05
  BUGZILLA:  1352476
  AFFECTED_RELEASE (ERRATA):
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 6) [httpd24-httpd-2.4.18-11.el6]: RHSA-2016:1420
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 7) [httpd24-httpd-2.4.18-11.el7]: RHSA-2016:1420
  PACKAGE_STATE:
   Not affected: Red Hat Directory Server 8 [httpd]
   Not affected: Red Hat JBoss Core Services 1 [jbcs-httpd24-httpd]
   Not affected: Red Hat JBoss EAP 5 [httpd]
   Not affected: Red Hat JBoss EAP 6 [httpd22]
   Not affected: Red Hat JBoss EAP 6 [httpd]
   Not affected: Red Hat JBoss EWS 1 [httpd]
   Not affected: Red Hat JBoss EWS 2 [httpd]
   Not affected: Red Hat JBoss Web Server 3.0 [httpd]
   Not affected: Red Hat Enterprise Linux 5 [httpd]
   Not affected: Red Hat Enterprise Linux 6 [httpd]
   Not affected: Red Hat Enterprise Linux 7 [httpd]

CVE-2016-5604
 Not present in Red Hat CVE database
 Try https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5604
```

```
$ rhsecapi --q-iava 2016-A-0287 -x -u -f affected_release
CVEs found: 4

rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2016-5604.json
Valid Red Hat CVE results retrieved: 3 of 4
Invalid CVE queries: 1 of 4

CVE-2015-7940 (https://access.redhat.com/security/cve/CVE-2015-7940)
  AFFECTED_RELEASE (ERRATA):
   Red Hat Jboss A-MQ 6.3: https://access.redhat.com/errata/RHSA-2016:2036
   Red Hat Jboss Fuse 6.3: https://access.redhat.com/errata/RHSA-2016:2035

CVE-2016-2107 (https://access.redhat.com/security/cve/CVE-2016-2107)
  AFFECTED_RELEASE (ERRATA):
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-48.el6_8.1]: https://access.redhat.com/errata/RHSA-2016:0996
   Red Hat Enterprise Linux 7 [openssl-1:1.0.1e-51.el7_2.5]: https://access.redhat.com/errata/RHSA-2016:0722
   Red Hat Enterprise Linux Extended Update Support 6.7 [openssl-1.0.1e-42.el6_7.5]: https://access.redhat.com/errata/RHSA-2016:2073

CVE-2016-4979 (https://access.redhat.com/security/cve/CVE-2016-4979)
  AFFECTED_RELEASE (ERRATA):
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 6) [httpd24-httpd-2.4.18-11.el6]: https://access.redhat.com/errata/RHSA-2016:1420
   Red Hat Software Collections for Red Hat Enterprise Linux Server (v. 7) [httpd24-httpd-2.4.18-11.el7]: https://access.redhat.com/errata/RHSA-2016:1420

CVE-2016-5604
 Not present in Red Hat CVE database
 Try https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5604
```

## Full help page

```
$ rhsecapi --help
usage: rhsecapi [--q-before YEAR-MM-DD] [--q-after YEAR-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT] [--q-package PKG]
                [--q-cwe CWEID] [--q-cvss SCORE] [--q-cvss3 SCORE] [--q-empty]
                [--q-pagesize PAGESZ] [--q-pagenum PAGENUM] [--q-raw RAWQUERY]
                [--q-iava IAVA] [-x] [-f FIELDS | -a | -m] [-j] [-u]
                [-w [WIDTH]] [-c] [-v] [-t THREDS] [-p] [-E [DAYS]] [-h]
                [--help]
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
  -x, --extract-search  Determine what CVEs to query by extracting them from
                        above search query (as initiated by at least one of
                        the --q-xxx options); note that this can be used at
                        the same time as manually specifying CVEs on cmdline
                        (below)
  CVE                   Retrieve a CVE or space-separated list of CVEs (e.g.:
                        'CVE-2016-5387')

CVE DISPLAY OPTIONS:
  -f, --fields FIELDS   Comma-separated fields to be displayed (default:
                        threat_severity, public_date, bugzilla,
                        affected_release, package_state); optionally prepend
                        with plus (+) sign to add fields to the default (e.g.,
                        '-f +iava,cvss3') or a caret (^) to remove fields from
                        the default (e.g., '-f ^bugzilla,threat_severity')
  -a, --all-fields      Print all supported fields (currently:
                        threat_severity, public_date, iava, cwe, cvss, cvss3,
                        bugzilla, acknowledgement, details, statement,
                        mitigation, upstream_fix, references,
                        affected_release, package_state)
  -m, --most-fields     Print all fields mentioned above except the heavy-text
                        ones -- (excluding: acknowledgement, details,
                        statement, mitigation, references)
  -j, --json            Print full & raw JSON output
  -u, --urls            Print URLs for all relevant fields

GENERAL OPTIONS:
  -w, --wrap [WIDTH]    Change wrap-width of long fields (acknowledgement,
                        details, statement, mitigation) in non-json output
                        (default: wrapping WIDTH equivalent to TERMWIDTH-2
                        unless using '--pastebin' where default WIDTH is
                        '168'; specify '0' to disable wrapping; WIDTH defaults
                        to '70' if option is used but WIDTH is omitted)
  -c, --count           Print a count of the number of entities found
  -v, --verbose         Print API urls to stderr
  -t, --threads THREDS  Set number of concurrent worker threads to allow when
                        making CVE queries (default on this system: 5)
  -p, --pastebin        Send output to Fedora Project Pastebin
                        (paste.fedoraproject.org) and print only URL to stdout
  -E, --pexpire [DAYS]  Set time in days after which paste will be deleted
                        (defaults to '28'; specify '0' to disable expiration;
                        DAYS defaults to '1' if option is used but DAYS is
                        omitted)
  -h                    Show short usage summary and exit
  --help                Show this help message and exit

VERSION:
  rhsecapi v0.7.0 last mod 2016/11/03
  See <http://github.com/ryran/redhat-security-data-api> to report bugs or RFEs
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
