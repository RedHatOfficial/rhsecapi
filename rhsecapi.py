#!/usr/bin/python2
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK
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

# Modules from standard library
from __future__ import print_function
import argparse
from sys import exit, stderr
import requests, json, re
import textwrap, fcntl, termios, struct
import multiprocessing
import copy_reg
import types

# Optional module
try:
    import argcomplete
    haveArgcomplete = True
except:
    print("Missing optional python module: argcomplete\n"
          "Install it to enable bash auto-magic tab-completion:\n"
          "  yum/dnf install python-pip; pip install argcomplete\n"
          "  activate-global-python-argcomplete; (Then restart shell)\n", file=stderr)
    haveArgcomplete = False

# Globals
prog = 'rhsecapi'
vers = {}
vers['version'] = '0.6.11'
vers['date'] = '2016/10/30'
# Set default number of threads to use
cpuCount = multiprocessing.cpu_count() + 1
# Supported CVE fields
allFields = ['threat_severity',
             'public_date',
             'iava',
             'cwe',
             'cvss',
             'cvss3',
             'bugzilla',
             'acknowledgement',
             'details',
             'statement',
             'mitigation',
             'upstream_fix',
             'references',
             'affected_release',
             'package_state',
             ]
# All supported fields minus the few text-heavy ones
mostFields = list(allFields)
notMostFields = ['acknowledgement',
                 'details',
                 'statement',
                 'mitigation',
                 'references',
                 ]
for f in notMostFields:
    mostFields.remove(f)
# Simple set of default fields
defaultFields = ['threat_severity',
                 'public_date',
                 'bugzilla',
                 'affected_release',
                 'package_state',
                 ]


def _reduce_method(m):
    if m.__self__ is None:
        return getattr, (m.__class__, m.__func__.__name__)
    else:
        return getattr, (m.__self__, m.__func__.__name__)


# Make it possible for pickle to serialize class functions
copy_reg.pickle(types.MethodType, _reduce_method)


def err_print_support_urls(msg=None):
    """Print error + support urls."""
    if msg:
        print(msg, file=stderr)
    print("For help, open an issue at http://github.com/ryran/redhat-security-data-api\n"
          "Or post a comment at https://access.redhat.com/discussions/2713931\n", file=stderr)


class RedHatSecDataApiClient:
    """Portable object to interface with the Red Hat Security Data API.

    https://access.redhat.com/documentation/en/red-hat-security-data-api/

    Requires:
      requests
      sys
    """
    def __init__(self, progressToStderr=False, apiurl='https://access.redhat.com/labs/securitydataapi'):
        self.apiurl = apiurl
        self.progressToStderr = progressToStderr

    def __validate_data_type(self, dt):
        dataTypes = ['cvrf', 'cve', 'oval']
        if dt not in dataTypes:
            raise ValueError("Invalid data type ('{0}') requested; should be one of: {1}".format(dt, ", ".join(dataTypes)))

    def __get(self, url, params={}):
        url = self.apiurl + url
        u = ""
        if params:
            for k in params:
                if params[k]:
                    u += "&{0}={1}".format(k, params[k])
            u = u.replace("&", "?", 1)
        if self.progressToStderr:
            print("Getting '{0}{1}' ...".format(url, u), file=stderr)
        r = requests.get(url, params=params)
        r.raise_for_status()
        return r.url, r.json()

    def _search(self, dataType, params=None):
        self.__validate_data_type(dataType)
        url = '/{0}.json'.format(dataType)
        if isinstance(params, dict):
            return self.__get(url, params)
        elif params:
            url += '?{0}'.format(params)
            return self.__get(url)

    def _retrieve(self, dataType, query):
        self.__validate_data_type(dataType)
        url = '/{0}/{1}.json'.format(dataType, query)
        return self.__get(url)

    def search_cvrf(self, params=None):
        return self._search('cvrf', params)

    def search_cve(self, params=None):
        return self._search('cve', params)

    def search_oval(self, params=None):
        return self._search('oval', params)

    def get_cvrf(self, rhsa):
        return self._retrieve('cvrf', rhsa)

    def get_cvrf_oval(self, rhsa):
        return self._retrieve('cvrf', '{0}/oval'.format(rhsa))

    def get_cve(self, cve):
        return self._retrieve('cve', cve)

    def get_oval(self, rhsa):
        return self._retrieve('oval', rhsa)


def fpaste_it(inputdata, lang='text', author=None, password=None, private='no', expire=28, project=None, url='http://paste.fedoraproject.org'):
    """Submit a new paste to fedora project pastebin."""
    # Establish critical params
    params = {
        'paste_data': inputdata,
        'paste_lang': lang,
        'api_submit': 'true',
        'mode': 'json',
        'paste_private': private,
        'paste_expire': str(expire*24*60*60),
        }
    # Add optional params
    if password:
        params['paste_password'] = password
    if project:
        params['paste_project'] = project
    if author:
        # If author is too long, truncate
        if len(author) > 50:
            author = author[0:47] + "..."
        params['paste_user'] = author
    # Check size of what we're about to post and raise exception if too big
    # FIXME: Figure out how to do this in requests without wasteful call to urllib.urlencode()
    from urllib import urlencode
    p = urlencode(params)
    pasteSizeKiB = len(p)/1024.0
    if pasteSizeKiB >= 512:
        raise ValueError("Fedora Pastebin client: WARN: paste size ({0:.1f} KiB) too large (max size: 512 KiB)".format(pasteSizeKiB))
    # Print status, then connect
    print("Fedora Pastebin client: INFO: Uploading {0:.1f} KiB...".format(pasteSizeKiB), file=stderr)
    r = requests.post(url, params)
    r.raise_for_status()
    try:
        j = r.json()
    except:
        # If no json returned, we've hit some weird error
        from tempfile import NamedTemporaryFile
        tmp = NamedTemporaryFile(delete=False)
        print(r.content, file=tmp)
        tmp.flush()
        raise ValueError("Fedora Pastebin client: ERROR: Didn't receive expected JSON response (saved to '{0}' for debugging)".format(tmp.name))
    # Error keys adapted from Jason Farrell's fpaste
    if j.has_key('error'):
        err = j['error']
        if err == 'err_spamguard_php':
            raise ValueError("Fedora Pastebin server: ERROR: Poster's IP rejected as malicious")
        elif err == 'err_spamguard_noflood':
            raise ValueError("Fedora Pastebin server: ERROR: Poster's IP rejected as trying to flood")
        elif err == 'err_spamguard_stealth':
            raise ValueError("Fedora Pastebin server: ERROR: Paste input triggered spam filter")
        elif err == 'err_spamguard_ipban':
            raise ValueError("Fedora Pastebin server: ERROR: Poster's IP rejected as permanently banned")
        elif err == 'err_author_numeric':
            raise ValueError("Fedora Pastebin server: ERROR: Poster's author should be alphanumeric")
        else:
            raise ValueError("Fedora Pastebin server: ERROR: '{0}'".format(err))
    # Put together URL with optional hash if requested
    pasteUrl = '{0}/{1}'.format(url, j['result']['id'])
    if 'yes' in private and j['result'].has_key('hash'):
        pasteUrl += '/{0}'.format(j['result']['hash'])
    return pasteUrl


def jprint(jsoninput, printOutput=True):
    """Pretty-print jsoninput."""
    j = json.dumps(jsoninput, sort_keys=True, indent=2)
    if printOutput:
        print(j)
    else:
        return j


class CustomFormatter(argparse.RawDescriptionHelpFormatter):
    """This custom formatter eliminates the duplicate metavar in help lines."""
    def _format_action_invocation(self, action):
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                for option_string in action.option_strings:
                    parts.append('%s' % option_string)
                parts[-1] += ' %s'%args_string
            return ', '.join(parts)


def parse_args():
    """Parse argv into usable input."""
    description = ("Make queries against the Red Hat Security Data API\n"
                   "Original announcement: https://access.redhat.com/blogs/766093/posts/2387601\n"
                   "Docs: https://access.redhat.com/documentation/en/red-hat-security-data-api/\n")
    version = "{0} v{1} last mod {2}".format(prog, vers['version'], vers['date'])
    epilog = (
        "VERSION:\n"
        "  {0}\n"
        "  See <http://github.com/ryran/redhat-security-data-api> to report bugs or RFEs").format(version)
    fmt = lambda prog: CustomFormatter(prog)
    p = argparse.ArgumentParser(
        prog=prog,
        description=description,
        add_help=False,
        epilog=epilog,
        formatter_class=fmt)
    # New group
    g_listByAttr = p.add_argument_group(
        'FIND CVES BY ATTRIBUTE')
    g_listByAttr.add_argument(
        '--q-before', metavar='YEAR-MM-DD',
        help="Narrow down results to before a certain time period")
    g_listByAttr.add_argument(
        '--q-after', metavar='YEAR-MM-DD',
        help="Narrow down results to after a certain time period")
    g_listByAttr.add_argument(
        '--q-bug', metavar='BZID',
        help="Narrow down results by Bugzilla ID (specify one or more, e.g.: '1326598,1084875')")
    g_listByAttr.add_argument(
        '--q-advisory', metavar='RHSA',
        help="Narrow down results by errata advisory (specify one or more, e.g.: 'RHSA-2016:0614,RHSA-2016:0610')")
    g_listByAttr.add_argument(
        '--q-severity', metavar='IMPACT', choices=['low', 'moderate', 'important', 'critical'],
        help="Narrow down results by severity rating (specify one of 'low', 'moderate', 'important', or 'critical')")
    g_listByAttr.add_argument(
        '--q-package', metavar='PKG',
        help="Narrow down results by package name (e.g.: 'samba' or 'thunderbird')")
    g_listByAttr.add_argument(
        '--q-cwe', metavar='CWEID',
        help="Narrow down results by CWE ID (specify one or more, e.g.: '295,300')")
    g_listByAttr.add_argument(
        '--q-cvss', metavar='SCORE',
        help="Narrow down results by CVSS base score (e.g.: '8.0')")
    g_listByAttr.add_argument(
        '--q-cvss3', metavar='SCORE',
        help="Narrow down results by CVSSv3 base score (e.g.: '5.1')")
    g_listByAttr.add_argument(
        '--q-empty', action='store_true',
        help="Allow performing an empty search; when used with no other --q-xxx options, this will return the first 1000 of the most recent CVEs (subject to below PAGESZ & PAGENUM)")
    g_listByAttr.add_argument(
        '--q-pagesize', metavar='PAGESZ', type=int,
        help="Set a cap on the number of results that will be returned (default: 1000)")
    g_listByAttr.add_argument(
        '--q-pagenum', metavar='PAGENUM', type=int,
        help="Select what page number to return (default: 1); only relevant when there are more than PAGESZ results")
    g_listByAttr.add_argument(
        '--q-raw', metavar='RAWQUERY', action='append',
        help="Narrow down results by RAWQUERY (e.g.: '--q-raw a=x --q-raw b=y'); this allows passing arbitrary params (e.g. something new that is unsupported by {0})".format(prog))
    # New group
    g_listByIava = p.add_argument_group(
        'FIND CVES BY IAVA')
    g_listByIava.add_argument(
        '--q-iava', metavar='IAVA',
        help="Narrow down results by IAVA number (e.g.: '2016-A-0293'); note however that this feature is not provided by the Red Hat Security Data API and thus: (1) it requires login to the Red Hat Customer Portal and (2) it cannot be used in concert with any of the above search parameters")
    # New group
    g_getCve = p.add_argument_group(
        'QUERY SPECIFIC CVES')
    g_getCve.add_argument(
        '-x', '--extract-search', action='store_true',
        help="Determine what CVEs to query by extracting them from above search query (as initiated by at least one of the --q-xxx options); this option suppresses usual JSON result of search queries")
    g_getCve.add_argument('cves', metavar='CVE', nargs='*',
        help="Retrieve a CVE or space-separated list of CVEs (e.g.: 'CVE-2016-5387')")
    # New group
    g_cveDisplay = p.add_argument_group(
        'CVE DISPLAY OPTIONS')
    g_cveDisplay0 = g_cveDisplay.add_mutually_exclusive_group()
    g_cveDisplay0.add_argument(
        '-f', '--fields', metavar='+FIELDS', default=','.join(defaultFields),
        help="Comma-separated fields to be displayed (default: {0}); optionally prepend with plus (+) sign to add fields to the default (e.g., '-f +iava,cvss3')".format(", ".join(defaultFields)))
    g_cveDisplay0.add_argument(
        '-a', '--all-fields', dest='fields', action='store_const',
        const=','.join(allFields),
        help="Print all supported fields (currently: {0})".format(", ".join(allFields)))
    g_cveDisplay0.add_argument(
        '-m', '--most-fields', dest='fields', action='store_const',
        const=','.join(mostFields),
        help="Print all fields mentioned above except the heavy-text ones -- (excluding: {0})".format(", ".join(notMostFields)))
    g_cveDisplay.add_argument(
        '-j', '--json', action='store_true',
        help="Print full & raw JSON output")
    g_cveDisplay.add_argument(
        '-u', '--urls', dest='printUrls', action='store_true',
        help="Print URLs for all relevant fields")
    # New group
    g_general = p.add_argument_group(
        'GENERAL OPTIONS')
    g_general.add_argument(
        '-w', '--wrap', metavar='WIDTH', dest='wrapWidth', nargs='?', default=1, const=70, type=int,
        help="Change wrap-width of long fields (acknowledgement, details, statement) in non-json output (default: wrapping with WIDTH equivalent to TERMWIDTH-2; specify '0' to disable wrapping; WIDTH defaults to '70' if option is used but WIDTH is omitted")
    g_general.add_argument(
        '-c', '--count', action='store_true',
        help="Print a count of the number of entities found")
    g_general.add_argument(
        '-v', '--verbose', action='store_true',
        help="Print API urls to stderr")
    g_general.add_argument(
        '-t', '--threads', metavar='N', type=int, default=cpuCount,
        help="Set number of concurrent CVE queries to make (default on this system: {0})".format(cpuCount))
    g_general.add_argument(
        '-p', '--pastebin', action='store_true',
        help="Send output to Fedora Project Pastebin (paste.fedoraproject.org) and print only URL to stdout")
    # g_general.add_argument(
    #     '--p-lang', metavar='LANG', default='text',
    #     choices=['ABAP', 'Actionscript', 'ADA', 'Apache Log', 'AppleScript', 'APT sources.list', 'ASM (m68k)', 'ASM (pic16)', 'ASM (x86)', 'ASM (z80)', 'ASP', 'AutoIT', 'Backus-Naur form', 'Bash', 'Basic4GL', 'BlitzBasic', 'Brainfuck', 'C', 'C for Macs', 'C#', 'C++', 'C++ (with QT)', 'CAD DCL', 'CadLisp', 'CFDG', 'CIL / MSIL', 'COBOL', 'ColdFusion', 'CSS', 'D', 'Delphi', 'Diff File Format', 'DIV', 'DOS', 'DOT language', 'Eiffel', 'Fortran', "FourJ's Genero", 'FreeBasic', 'GetText', 'glSlang', 'GML', 'gnuplot', 'Groovy', 'Haskell', 'HQ9+', 'HTML', 'INI (Config Files)', 'Inno', 'INTERCAL', 'IO', 'Java', 'Java 5', 'Javascript', 'KiXtart', 'KLone C & C++', 'LaTeX', 'Lisp', 'LOLcode', 'LotusScript', 'LScript', 'Lua', 'Make', 'mIRC', 'MXML', 'MySQL', 'NSIS', 'Objective C', 'OCaml', 'OpenOffice BASIC', 'Oracle 8 & 11 SQL', 'Pascal', 'Perl', 'PHP', 'Pixel Bender', 'PL/SQL', 'POV-Ray', 'PowerShell', 'Progress (OpenEdge ABL)', 'Prolog', 'ProvideX', 'Python', 'Q(uick)BASIC', 'robots.txt', 'Ruby', 'Ruby on Rails', 'SAS', 'Scala', 'Scheme', 'Scilab', 'SDLBasic', 'Smalltalk', 'Smarty', 'SQL', 'T-SQL', 'TCL', 'thinBasic', 'TypoScript', 'Uno IDL', 'VB.NET', 'Verilog', 'VHDL', 'VIM Script', 'Visual BASIC', 'Visual Fox Pro', 'Visual Prolog', 'Whitespace', 'Winbatch', 'Windows Registry Files', 'X++', 'XML', 'Xorg.conf'],
    #     help="Set the development language for the paste (default: 'text')")
    # g_general.add_argument(
    #     '-A', '--p-author', metavar='NAME', default=prog,
    #     help="Set alphanumeric paste author (default: '{0}')".format(prog))
    # g_general.add_argument(
    #     '--p-password', metavar='PASSWD',
    #     help="Set password string to protect paste")
    # g_general.add_argument(
    #     '--p-public', dest='p_private', default='yes', action='store_const', const='no',
    #     help="Set paste to be publicly-discoverable")
    g_general.add_argument(
        '-E', '--pexpire', metavar='DAYS', nargs='?', const=2, default=28, type=int,
        help="Set time in days after which paste will be deleted (defaults to '28'; specify '0' to disable expiration; DAYS defaults to '2' if option is used but DAYS is omitted)")
    # g_general.add_argument(
    #     '--p-project', metavar='PROJECT',
    #     help="Associate paste with a project")
    g_general.add_argument(
        '-h', dest='showUsage', action='store_true',
        help="Show short usage summary and exit")
    g_general.add_argument(
        '--help', dest='showHelp', action='store_true',
        help="Show this help message and exit")
    if haveArgcomplete:
        # Parse and return
        argcomplete.autocomplete(p)
    o = p.parse_args()
    if o.showHelp:
        from tempfile import NamedTemporaryFile
        from subprocess import call
        tmp = NamedTemporaryFile(prefix='{0}-help-'.format(prog), suffix='.txt')
        p.print_help(file=tmp)
        tmp.flush()
        call(['less', tmp.name])
        exit()
    # Add search params to dict
    o.searchParams = {
        'before': o.q_before,
        'after': o.q_after,
        'bug': o.q_bug,
        'advisory': o.q_advisory,
        'severity': o.q_severity,
        'package': o.q_package,
        'cwe': o.q_cwe,
        'cvss_score': o.q_cvss,
        'cvss3_score': o.q_cvss3,
        'per_page': o.q_pagesize,
        'page': o.q_pagenum,
        }
    if o.q_raw:
        for param in o.q_raw:
            p = param.split("=")
            o.searchParams[p[0]] = p[1]
    if all(val is None for val in o.searchParams.values()) and not o.q_empty:
        o.doSearch = False
    else:
        o.doSearch = True
    if o.q_iava and o.doSearch:
        print("{0}: The --q-iava option is not compatible with other --q-xxx options; it can only be used alone".format(prog), file=stderr)
        exit(1)
    if len(o.cves) == 1 and not o.cves[0].startswith('CVE-'):
        o.showUsage = True
    if o.showUsage or not (o.doSearch or o.cves or o.q_iava):
        p.print_usage()
        print("\nRun {0} --help for full help page\n\n{1}".format(prog, epilog))
        exit()
    if o.fields.startswith('+'):
        o.fields = '{0},{1}'.format(','.join(defaultFields), o.fields[1:])
    return o


class RHSecApiParse:
    """Parse and print results returned from RedHatSecDataApiClient.

    Requires:
      RedHatSecDataApiClient
      json
      sys
      requests
      re

    Conditional:
      textwrap
      fcntl
      termios
      struct
    """


    def __init__(self,
                 fields='threat_severity,public_date,bugzilla,affected_release,package_state',
                 printUrls=False, rawOutput=False, onlyCount=False, verbose=False, wrapWidth=1):
        """Initialize class settings."""
        self.rhsda = RedHatSecDataApiClient(verbose)
        if len(fields):
            self.desiredFields = fields.split(",")
        else:
            self.desiredFields = []
        self.printUrls = printUrls
        self.rawOutput = rawOutput
        self.output = ""
        self.onlyCount = onlyCount
        self.cveCount = 0
        if wrapWidth == 1:
            wrapWidth = self.get_terminal_width() - 2
        if wrapWidth:
            self.w = textwrap.TextWrapper(width=wrapWidth, initial_indent="   ", subsequent_indent="   ", replace_whitespace=False)
        else:
            self.w = 0

    def get_terminal_width(self):
        h, w, hp, wp = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))
        return w

    def search_query(self, params):
        """Perform a CVE search query based on params."""
        try:
            url, result = self.rhsda.search_cve(params)
        except requests.exceptions.ConnectionError as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            err_print_support_urls()
            exit(1)
        except requests.exceptions.HTTPError as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            err_print_support_urls()
            exit(1)
        except requests.exceptions.RequestException as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            err_print_support_urls()
            exit(1)
        print("CVEs found: {0}".format(len(result)), file=stderr)
        if not self.onlyCount:
            print(file=stderr)
        return result   

    def _check_field(self, field, jsoninput):
        """Return True if field is desired and exists in jsoninput."""
        if field in self.desiredFields and jsoninput.has_key(field):
            return True
        return False

    def _stripjoin(self, input, oneLineEach=False):
        """Strip whitespace from input or input list."""
        text = ""
        if isinstance(input, list):
            for i in input:
                text += i.encode('utf-8').strip()
                if oneLineEach:
                    text += "\n"
                else:
                    text += "  "
        else:
            text = input.encode('utf-8').strip()
        if oneLineEach:
            text = re.sub(r"\n+", "\n   ", text)
        else:
            text = re.sub(r"\n+", "  ", text)
        if self.w:
            text = "\n" + "\n".join(self.w.wrap(text))
        return text

    def print_cve(self, cve):
        """Print CVE data."""
        out = []
        try:
            requrl, j = self.rhsda.get_cve(cve)
        except requests.exceptions.ConnectionError as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            err_print_support_urls()
            exit(1)
        except requests.exceptions.HTTPError as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            if not self.onlyCount:
                out.append("{0}\n Not present in Red Hat CVE database\n".format(cve))
                if cve.startswith("CVE-"):
                    out.append(" Try https://cve.mitre.org/cgi-bin/cvename.cgi?name={0}\n\n".format(cve))
            return "".join(out), False
        except requests.exceptions.RequestException as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            err_print_support_urls()
            exit(1)

        # If --count was used, done
        if self.onlyCount:
            return "".join(out), True

        # If --json was used, done
        if self.rawOutput:
            out.append(jprint(j, False) + "\n")
            return "".join(out), True

        # CVE name always printed
        name = ""
        if cve != j['name']:
            name = " [{0}]".format(j['name'])
        url = ""
        if self.printUrls:
            url = " (https://access.redhat.com/security/cve/{0})".format(cve)
        out.append("{0}{1}{2}\n".format(cve, name, url))

        # If --fields='' was used, done
        if not self.desiredFields:
            return "".join(out), True

        if self._check_field('threat_severity', j):
            url = ""
            if self.printUrls:
                url = " (https://access.redhat.com/security/updates/classification)"
            out.append("  IMPACT:  {0}{1}\n".format(j['threat_severity'], url))

        if self._check_field('public_date', j):
            out.append("  DATE:  {0}\n".format(j['public_date'].split("T")[0]))

        if self._check_field('iava', j):
            out.append("  IAVA:")
            if self.printUrls:
                out.append("\n")
                iavas = j['iava'].split(",")
                for i in iavas:
                    i = i.strip()
                    url = " (https://access.redhat.com/labs/iavmmapper/api/iava/{0})".format(i)
                    out.append("   {0}{1}\n".format(i, url))
            else:
                out.append("  {0}\n".format(j['iava']))

        if self._check_field('cwe', j):
            out.append("  CWE:  {0}".format(j['cwe']))
            if self.printUrls:
                cwes = re.findall("CWE-[0-9]+", j['cwe'])
                if len(cwes) == 1:
                    out.append(" (http://cwe.mitre.org/data/definitions/{0}.html)\n".format(cwes[0].lstrip("CWE-")))
                else:
                    out.append("\n")
                    for c in cwes:
                        out.append("   http://cwe.mitre.org/data/definitions/{0}.html\n".format(c.lstrip("CWE-")))
            else:
                out.append("\n")

        if self._check_field('cvss', j):
            cvss_scoring_vector = j['cvss']['cvss_scoring_vector']
            if self.printUrls:
                cvss_scoring_vector = "http://nvd.nist.gov/cvss.cfm?version=2&vector={0}".format(cvss_scoring_vector)
            out.append("  CVSS:  {0} ({1})\n".format(j['cvss']['cvss_base_score'], cvss_scoring_vector))

        if self._check_field('cvss3', j):
            cvss3_scoring_vector = j['cvss3']['cvss3_scoring_vector']
            if self.printUrls:
                cvss3_scoring_vector = "https://www.first.org/cvss/calculator/3.0#{0}".format(cvss3_scoring_vector)
            out.append("  CVSS3:  {0} ({1})\n".format(j['cvss3']['cvss3_base_score'], cvss3_scoring_vector))

        if 'bugzilla' in self.desiredFields:
            if j.has_key('bugzilla'):
                if self.printUrls:
                    bug = j['bugzilla']['url']
                else:
                    bug = j['bugzilla']['id']
                out.append("  BUGZILLA:  {0}\n".format(bug))
            else:
                out.append("  BUGZILLA:  No Bugzilla data\n")
                out.append("   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy\n")

        if self._check_field('acknowledgement', j):
            out.append("  ACKNOWLEDGEMENT:  {0}\n".format(self._stripjoin(j['acknowledgement'])))

        if self._check_field('details', j):
            out.append("  DETAILS:  {0}\n".format(self._stripjoin(j['details'])))

        if self._check_field('statement', j):
            out.append("  STATEMENT:  {0}\n".format(self._stripjoin(j['statement'])))

        if self._check_field('mitigation', j):
            out.append("  MITIGATION:  {0}\n".format(self._stripjoin(j['mitigation'])))

        if self._check_field('upstream_fix', j):
            out.append("  UPSTREAM_FIX:  {0}\n".format(j['upstream_fix']))

        if self._check_field('references', j):
            out.append("  REFERENCES:{0}\n".format(self._stripjoin(j['references'], oneLineEach=True)))

        if self._check_field('affected_release', j):
            out.append("  AFFECTED_RELEASE (ERRATA):\n")
            affected_release = j['affected_release']
            if isinstance(affected_release, dict):
                # When there's only one, it doesn't show up in a list
                affected_release = [affected_release]
            for release in affected_release:
                package = ""
                if release.has_key('package'):
                    package = " [{0}]".format(release['package'])
                advisory = release['advisory']
                if self.printUrls:
                    advisory = "https://access.redhat.com/errata/{0}".format(advisory)
                out.append("   {0}{1}: {2}\n".format(release['product_name'], package, advisory))

        if self._check_field('package_state', j):
            out.append("  PACKAGE_STATE:\n")
            package_state = j['package_state']
            if isinstance(package_state, dict):
                # When there's only one, it doesn't show up in a list
                package_state = [package_state]
            for state in package_state:
                package_name = ""
                if state.has_key('package_name'):
                    package_name = " [{0}]".format(state['package_name'])
                out.append("   {2}: {0}{1}\n".format(state['product_name'], package_name, state['fix_state']))

        # Add one final newline to the end
        out.append("\n")
        return "".join(out), True


def iavm_query(url, progressToStderr=False):
    """Get IAVA json from IAVM Mapper App."""
    if progressToStderr:
        print("Getting '{0}' ...".format(url), file=stderr)
    try:
        r = requests.get(url, auth=())
    except requests.exceptions.ConnectionError as e:
        print("{0}: {1}".format(prog, e), file=stderr)
        err_print_support_urls()
        exit(1)
    except requests.exceptions.HTTPError as e:
        print("{0}: {1}".format(prog, e), file=stderr)
        err_print_support_urls()
        exit(1)
    except requests.exceptions.RequestException as e:
        print("{0}: {1}".format(prog, e), file=stderr)
        err_print_support_urls()
        exit(1)
    try:
         result = r.json()
    except:
        print("{0}: Login error; unable to get IAVA info\n\n"
              "IAVA->CVE mapping data is not provided by the public RH Security Data API.\n"
              "Instead, this uses the IAVM Mapper App (access.redhat.com/labs/iavmmapper).\n\n"
              "Access to this data requires RH Customer Portal credentials be provided.\n"
              "Create a ~/.netrc with the following contents:\n\n"
              "machine access.redhat.com\n"
              "  login YOUR-CUSTOMER-PORTAL-LOGIN\n"
              "  password YOUR_PASSWORD_HERE\n".format(prog),
              file=stderr)
        err_print_support_urls()
        exit(1)
    return result


def get_iava(iavaId, progressToStderr=False, onlyCount=False):
    """Validate IAVA number and return json."""
    url = 'https://access.redhat.com/labs/iavmmapper/api/iava/'
    result = iavm_query(url, progressToStderr=progressToStderr)
    if iavaId not in result:
        print("{0}: IAVM Mapper (https://access.redhat.com/labs/iavmmapper) has no knowledge of '{1}'\n".format(prog, iavaId), file=stderr)
        err_print_support_urls()
        exit(1)
    url += '{0}'.format(iavaId)
    result = iavm_query(url, progressToStderr=progressToStderr)
    try:
        print("CVEs found: {0}".format(len(result['IAVM']['CVEs']['CVENumber'])), file=stderr)
    except:
        err_print_support_urls()
        raise
    if not onlyCount:
        print(file=stderr)
    return result


def main(opts):
    a = RHSecApiParse(opts.fields, opts.printUrls, opts.json, opts.count, opts.verbose, opts.wrapWidth)
    searchOutput = []
    iavaOutput = []
    cveOutput = []
    if opts.doSearch:
        result = a.search_query(opts.searchParams)
        if opts.extract_search:
            if result:
                for i in result:
                    opts.cves.append(i['CVE'])
        elif not opts.count:
            if opts.json:
                searchOutput.append(jprint(result, False) + "\n")
            else:
                for cve in result:
                    searchOutput.append(cve['CVE'] + "\n")
            if not opts.pastebin:
                print("".join(searchOutput))
    elif opts.q_iava:
        result = get_iava(opts.q_iava, opts.verbose, opts.count)
        if opts.extract_search:
            if result:
                opts.cves.extend(result['IAVM']['CVEs']['CVENumber'])
        elif not opts.count:
            if opts.json:
                iavaOutput.append(jprint(result, False) + "\n")
            else:
                for cve in result['IAVM']['CVEs']['CVENumber']:
                    iavaOutput.append(cve + "\n")
            if not opts.pastebin:
                print("".join(iavaOutput))
    if opts.cves:
        if searchOutput:
            searchOutput.append("\n")
        if iavaOutput:
            iavaOutput.append("\n")
        pool = multiprocessing.Pool(opts.threads)
        results = pool.map(a.print_cve, opts.cves)
        pool.close()
        pool.join()
        cveOutput, successValues = zip(*results)
        total = len(opts.cves)
        valid = successValues.count(True)
        print("Valid Red Hat CVE results retrieved: {0} of {1}".format(valid, total), file=stderr)
        if valid != total:
            print("Invalid CVE queries: {0} of {1}".format(successValues.count(False), total), file=stderr)
        print(file=stderr)
    if opts.count:
        return
    if opts.pastebin:
        opts.p_lang = 'text'
        if opts.json or not opts.cves:
            opts.p_lang = 'Python'
        data = "".join(searchOutput) + "".join(iavaOutput) + "".join(cveOutput)
        try:
            response = fpaste_it(inputdata=data, author=prog, lang=opts.p_lang, expire=opts.pexpire)
        except ValueError as e:
            print(e, file=stderr)
            print("{0}: Submitting to pastebin failed; print results to stdout instead? [y]".format(prog), file=stderr)
            answer = raw_input("> ")
            if "y" in answer or len(answer) == 0:
                print(data, end="")
        else:
            print(response)
    elif opts.cves:
        print("".join(cveOutput), end="")
    


if __name__ == "__main__":
    try:
        opts = parse_args()
        main(opts)
    except KeyboardInterrupt:
        print("\nReceived KeyboardInterrupt. Exiting.")
        exit()
else:
    a = RedHatSecDataApiClient(True)