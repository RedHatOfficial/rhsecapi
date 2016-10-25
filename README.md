# redhat-security-data-api

Threw this new `rhsecapi` tool together quickly to interface with the [Red Hat Security Data API](https://access.redhat.com/documentation/en/red-hat-security-data-api/).

No promises that anything will stay the same as long as it's under 1.0 and the API is still beta. I might change the name or the options. I haven't thoroughly-tested yet. (Expect further releases.) I welcome feedback/issues and pull requests. If you don't have a GitHub account but do have a Red Hat Portal login, go here: [New cmdline tool: redhat-security-data-api - rhsecapi](https://access.redhat.com/discussions/2713931).

### Simple CVE Queries

```
$ rhsecapi CVE-2004-0230 CVE-2015-4642 CVE-2010-5298
CVE-2004-0230
  BUGZILLA:  No Bugzilla data
   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy

rhsecapi: 404 Client Error: Not Found for url: https://access.redhat.com/labs/securitydataapi/cve/CVE-2015-4642.json
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

### BASH intelligent tab-completion

```
$ rhsecapi --
-a                -f                -m                --q-advisory      --q-cwe           --urls
--all-fields      --fields          --most-fields     --q-after         --q-package       -v
-c                -h                -p                --q-before        --q-raw           --verbose
--count           --help            --pastebin        --q-bug           --q-severity      -w
-E                -j                --p-expire        --q-cvss          -u                --wrap
--extract-search  --json            --p-user          --q-cvss3         -U                -x
```

### Field display

```
$ rhsecapi CVE-2016-5387 --fields cvss,cvss3
CVE-2016-5387
  CVSS:  5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)
  CVSS3:  5.0 (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N)
```

```
$ rhsecapi --fields +cvss,cwe CVE-2015-6525 --urls
CVE-2015-6525 (https://access.redhat.com/security/cve/CVE-2015-6525)
  IMPACT:  Moderate (https://access.redhat.com/security/updates/classification)
  DATE:  2015-08-24
  CWE:  CWE-190->(CWE-122|CWE-835)
   http://cwe.mitre.org/data/definitions/190.html
   http://cwe.mitre.org/data/definitions/122.html
   http://cwe.mitre.org/data/definitions/835.html
  CVSS:  5.1 (http://nvd.nist.gov/cvss.cfm?version=2&vector=AV:N/AC:H/Au:N/C:P/I:P/A:P)
  BUGZILLA:  https://bugzilla.redhat.com/show_bug.cgi?id=1256797
  PACKAGE_STATE:
   Not affected: Red Hat Enterprise Linux 4 [nfs-utils]
   Not affected: Red Hat Enterprise Linux 4 [openmpi]
   Not affected: Red Hat Enterprise Linux 5 [libevent]
   Not affected: Red Hat Enterprise Linux 5 [openmpi]
   Will not fix: Red Hat Enterprise Linux 5 [firefox]
   Will not fix: Red Hat Enterprise Linux 5 [thunderbird]
   Not affected: Red Hat Enterprise Linux 6 [libevent]
   Not affected: Red Hat Enterprise Linux 6 [openmpi]
   Will not fix: Red Hat Enterprise Linux 6 [chromium-browser]
   Will not fix: Red Hat Enterprise Linux 6 [firefox]
   Will not fix: Red Hat Enterprise Linux 6 [thunderbird]
   Fix deferred: Red Hat Enterprise Linux 7 [libevent]
   Not affected: Red Hat Enterprise Linux 7 [openmpi]
   Will not fix: Red Hat Enterprise Linux 7 [firefox]
   Will not fix: Red Hat Enterprise Linux 7 [thunderbird]
```

```
$ rhsecapi CVE-2010-5298 -f +iava,cvss
CVE-2010-5298
  IMPACT:  Moderate
  DATE:  2014-04-08
  IAVA:  2014-A-0100, 2014-B-0077, 2014-B-0088, 2014-B-0089, 2014-B-0091, 2014-B-0092, 2014-B-0097, 2014-B-0101, 2014-B-0102
  CVSS:  4.3 (AV:N/AC:M/Au:N/C:N/I:N/A:P)
  BUGZILLA:  1087195
  AFFECTED_RELEASE (ERRATA):
   Red Hat Enterprise Linux 6 [openssl-1.0.1e-16.el6_5.14]: RHSA-2014:0625
   Red Hat Enterprise Linux 7 [openssl-1:1.0.1e-34.el7_0.3]: RHSA-2014:0679
   Red Hat Storage Server 2.1 [openssl-1.0.1e-16.el6_5.14]: RHSA-2014:0628
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

```
$ rhsecapi CVE-2016-5387 --all-fields
CVE-2016-5387
  IMPACT:  Important
  DATE:  2016-07-18
  CWE:  CWE-20
  CVSS:  5.0 (AV:N/AC:L/Au:N/C:N/I:P/A:N)
  CVSS3:  5.0 (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N)
  BUGZILLA:  1353755
  ACKNOWLEDGEMENT:  
   Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue.
  DETAILS:  
   The Apache HTTP Server through 2.4.23 follows RFC 3875 section 4.1.18 and therefore
   does not protect applications from the presence of untrusted client data in the
   HTTP_PROXY environment variable, which might allow remote attackers to redirect an
   application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy
   header in an HTTP request, aka an "httpoxy" issue.  NOTE: the vendor states "This
   mitigation has been assigned the identifier CVE-2016-5387"; in other words, this is not
   a CVE ID for a vulnerability.  It was discovered that httpd used the value of the Proxy
   header from HTTP requests to initialize the HTTP_PROXY environment variable for CGI
   scripts, which in turn was incorrectly used by certain HTTP client implementations to
   configure the proxy for outgoing HTTP requests. A remote attacker could possibly use
   this flaw to redirect HTTP requests performed by a CGI script to an attacker-controlled
   proxy via a malicious HTTP request.
  UPSTREAM_FIX:  httpd 2.4.24, httpd 2.2.32
  REFERENCES:  
   https://access.redhat.com/security/vulnerabilities/httpoxy
   https://httpoxy.org/
   https://www.apache.org/security/asf-httpoxy-response.txt
  AFFECTED_RELEASE (ERRATA):
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
  PACKAGE_STATE:
   Affected: Red Hat JBoss EAP 6 [httpd22]
   Not affected: Red Hat JBoss EAP 7 [httpd22]
   Will not fix: Red Hat JBoss EWS 1 [httpd]
```

### Search queries

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-12-01 --q-severity critical
Search query results found: 1

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
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-10-01 --count
Search query results found: 6
```

```
$ rhsecapi --q-package rhev-hypervisor6 --q-after 2014-10-01 --extract-search --fields=''
Search query results found: 6

CVE-2015-3456
CVE-2015-0235
CVE-2014-3611
CVE-2014-3645
CVE-2014-3646
CVE-2014-3567
```

### Help page

```
$ rhsecapi -h
usage: rhsecapi [--q-before YEAR-MM-DD] [--q-after YEAR-MM-DD] [--q-bug BZID]
                [--q-advisory RHSA] [--q-severity IMPACT] [--q-package PKG]
                [--q-cwe CWEID] [--q-cvss SCORE] [--q-cvss3 SCORE]
                [--q-raw RAWQUERY] [-x] [-f FIELDS | -a | -m | -j] [-u]
                [-w [WIDTH]] [-c] [-v] [-p] [-U NAME] [-E [DAYS]] [-h]
                [--help]
                [CVE [CVE ...]]

Make queries against the Red Hat Security Data API
Original announcement: https://access.redhat.com/blogs/766093/posts/2387601
Docs: https://access.redhat.com/documentation/en/red-hat-security-data-api/

PERFORM GENERAL SEARCH QUERY:
  Initiate a single search query and print JSON results

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
  --q-raw RAWQUERY      Narrow down results by RAWQUERY (e.g.: 'per_page=500'
                        or 'a=b&x=y'

PERFORM CVE QUERIES:
  Search by CVE in addition to or instead above search query

  CVE                   Query a CVE or space-separated list of CVEs (e.g.:
                        'CVE-2016-5387')
  -x, --extract-search  Determine what CVEs to query by extracting them from
                        general search query as initiated by at least one of
                        the GENERAL SEARCH QUERY options (suppresses usual
                        JSON result of search query)

CVE QUERY DISPLAY OPTIONS:
  -f, --fields FIELDS   Comma-separated fields to be displayed (default:
                        threat_severity, bugzilla, affected_release,
                        package_state)
  -a, --all-fields      Print all supported fields (currently:
                        threat_severity, public_date, iava, cwe, cvss, cvss3,
                        bugzilla, acknowledgement, details, statement,
                        affected_release, package_state)
  -m, --most-fields     Print all fields mentioned above except the heavy-text
                        ones -- acknowledgement, details, statement
  -j, --json            Print full & raw JSON output
  -u, --urls            Print URLs for all relevant fields

GENERAL OPTIONS:
  -w, --wrap [WIDTH]    Change wrap-width of long fields (acknowledgement,
                        details, statement) in non-json output (default:
                        wrapping with WIDTH equivalent to TERMWIDTH-2; specify
                        '0' to disable wrapping; WIDTH defaults to '70' if
                        option is used but WIDTH is omitted
  -c, --count           Print a count of the number of entities found
  -v, --verbose         Print API urls to stderr
  -p, --pastebin        Send output to Fedora Project Pastebin
                        (paste.fedoraproject.org) and print only URL to stdout
  -U, --p-user NAME     Set alphanumeric paste author (default: 'rhsecapi')
  -E, --p-expire [DAYS]
                        Set time in days after which paste will be deleted
                        (defaults to '28'; specify '0' to disable expiration;
                        DAYS defaults to '2' if option is used but DAYS is
                        omitted)
  -h                    Show short usage summary and exit
  --help                Show this help message and exit

VERSION:
  rhsecapi v0.1.6 last mod 2016/10/24
  See <http://github.com/ryran/redhat-security-data-api> to report bugs or RFEs
```

### Testing from python shell

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
('https://access.redhat.com/labs/securitydataapi/oval.json?cve=CVE-2016-5387', [{u'severity': u'important', u'bugzillas': [u'1353755'], u'resource_url': u'https://access.redhat.com/labs/securitydataapi/oval/RHSA-2016:1421.json', u'released_on': u'2016-07-18T04:00:00+00:00', u'RHSA': u'RHSA-2016:1421', u'CVEs': [u'CVE-2016-5387']}, {u'severity': u'important', u'bugzillas': [u'1347648', u'1353269', u'1353755'], u'resource_url': u'https://access.redhat.com/labs/securitydataapi/oval/RHSA-2016:1422.json', u'released_on': u'2016-07-18T04:00:00+00:00', u'RHSA': u'RHSA-2016:1422', u'CVEs': [u'CVE-2016-5387']}])
>>> r.jprint(r.a.search_oval("cve=CVE-2016-5387"))
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
