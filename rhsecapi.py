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
vers['version'] = '0.1.9'
vers['date'] = '2016/10/25'
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

    def __get(self, url):
        url = self.apiurl + url
        if self.progressToStderr:
            print("Getting '{0}' ...".format(url), file=stderr)
        r = requests.get(url)
        r.raise_for_status()
        return url, r.json()

    def _search(self, dataType, params=None):
        self.__validate_data_type(dataType)
        url = '/{0}.json'.format(dataType)
        if params:
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


def fpaste_it(inputdata, lang='text', user=None, password=None, private='yes', expire=28, project=None, url='http://paste.fedoraproject.org'):
    """Submit a new paste to fedora project pastebin."""
    p = {
        'paste_data': inputdata,
        'paste_lang': lang,
        'api_submit': 'true',
        'mode': 'json',
        'paste_private': private,
        'paste_expire': str(expire*24*60*60),
        }
    if user:
        p['paste_user'] = user
    if password:
        p['paste_password'] = password
    if project:
        p['paste_project'] = project
    r = requests.post(url, p)
    r.raise_for_status()
    j = r.json()
    if j.has_key('error'):
        jprint(j)
        exit(1)
    pasteUrl = '{0}/{1}'.format(url, j['result']['id'])
    if 'yes' in private and j['result'].has_key('hash'):
        pasteUrl += '/{0}'.format(j['result']['hash'])
    print(pasteUrl)


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
    # Add args
    g0 = p.add_argument_group(
        'PERFORM GENERAL SEARCH QUERY',
        description="Initiate a single search query and print JSON results")
    g0.add_argument(
        '--q-before', metavar='YEAR-MM-DD',
        help="Narrow down results to before a certain time period")
    g0.add_argument(
        '--q-after', metavar='YEAR-MM-DD',
        help="Narrow down results to after a certain time period")
    g0.add_argument(
        '--q-bug', metavar='BZID',
        help="Narrow down results by Bugzilla ID (specify one or more, e.g.: '1326598,1084875')")
    g0.add_argument(
        '--q-advisory', metavar='RHSA',
        help="Narrow down results by errata advisory (specify one or more, e.g.: 'RHSA-2016:0614,RHSA-2016:0610')")
    g0.add_argument(
        '--q-severity', metavar='IMPACT', choices=['low', 'moderate', 'important', 'critical'],
        help="Narrow down results by severity rating (specify one of 'low', 'moderate', 'important', or 'critical')")
    g0.add_argument(
        '--q-package', metavar='PKG',
        help="Narrow down results by package name (e.g.: 'samba' or 'thunderbird')")
    g0.add_argument(
        '--q-cwe', metavar='CWEID',
        help="Narrow down results by CWE ID (specify one or more, e.g.: '295,300')")
    g0.add_argument(
        '--q-cvss', metavar='SCORE',
        help="Narrow down results by CVSS base score (e.g.: '8.0')")
    g0.add_argument(
        '--q-cvss3', metavar='SCORE',
        help="Narrow down results by CVSSv3 base score (e.g.: '5.1')")
    g0.add_argument(
        '--q-raw', metavar='RAWQUERY',
        help="Narrow down results by RAWQUERY (e.g.: 'per_page=500' or 'a=b&x=y'")
    g00 = p.add_argument_group(
        'PERFORM CVE QUERIES',
        description="Search by CVE in addition to or instead above search query")
    g00.add_argument('cves', metavar='CVE', nargs='*',
        help="Query a CVE or space-separated list of CVEs (e.g.: 'CVE-2016-5387')")
    g00.add_argument(
        '-x', '--extract-search', action='store_true',
        help="Determine what CVEs to query by extracting them from general search query as initiated by at least one of the GENERAL SEARCH QUERY options (suppresses usual JSON result of search query)")
    g1 = p.add_argument_group(
        'CVE QUERY DISPLAY OPTIONS')
    gg1 = g1.add_mutually_exclusive_group()
    gg1.add_argument(
        '-f', '--fields', metavar='+FIELDS', default=','.join(defaultFields),
        help="Comma-separated fields to be displayed (default: {0}); optionally prepend with plus (+) sign to add fields to the default (e.g., '-f +iava,cvss3')".format(", ".join(defaultFields)))
    gg1.add_argument(
        '-a', '--all-fields', dest='fields', action='store_const',
        const=','.join(allFields),
        help="Print all supported fields (currently: {0})".format(", ".join(allFields)))
    gg1.add_argument(
        '-m', '--most-fields', dest='fields', action='store_const',
        const=','.join(mostFields),
        help="Print all fields mentioned above except the heavy-text ones -- (excluding: {0})".format(", ".join(notMostFields)))
    gg1.add_argument(
        '-j', '--json', action='store_true',
        help="Print full & raw JSON output")
    g1.add_argument(
        '-u', '--urls', dest='printUrls', action='store_true',
        help="Print URLs for all relevant fields")
    g2 = p.add_argument_group(
        'GENERAL OPTIONS')
    g2.add_argument(
        '-w', '--wrap', metavar='WIDTH', dest='wrapWidth', nargs='?', default=1, const=70, type=int,
        help="Change wrap-width of long fields (acknowledgement, details, statement) in non-json output (default: wrapping with WIDTH equivalent to TERMWIDTH-2; specify '0' to disable wrapping; WIDTH defaults to '70' if option is used but WIDTH is omitted")
    g2.add_argument(
        '-c', '--count', action='store_true',
        help="Print a count of the number of entities found")
    g2.add_argument(
        '-v', '--verbose', action='store_true',
        help="Print API urls to stderr")
    g2.add_argument(
        '-p', '--pastebin', action='store_true',
        help="Send output to Fedora Project Pastebin (paste.fedoraproject.org) and print only URL to stdout")
    # g2.add_argument(
    #     '--p-lang', metavar='LANG', default='text',
    #     choices=['ABAP', 'Actionscript', 'ADA', 'Apache Log', 'AppleScript', 'APT sources.list', 'ASM (m68k)', 'ASM (pic16)', 'ASM (x86)', 'ASM (z80)', 'ASP', 'AutoIT', 'Backus-Naur form', 'Bash', 'Basic4GL', 'BlitzBasic', 'Brainfuck', 'C', 'C for Macs', 'C#', 'C++', 'C++ (with QT)', 'CAD DCL', 'CadLisp', 'CFDG', 'CIL / MSIL', 'COBOL', 'ColdFusion', 'CSS', 'D', 'Delphi', 'Diff File Format', 'DIV', 'DOS', 'DOT language', 'Eiffel', 'Fortran', "FourJ's Genero", 'FreeBasic', 'GetText', 'glSlang', 'GML', 'gnuplot', 'Groovy', 'Haskell', 'HQ9+', 'HTML', 'INI (Config Files)', 'Inno', 'INTERCAL', 'IO', 'Java', 'Java 5', 'Javascript', 'KiXtart', 'KLone C & C++', 'LaTeX', 'Lisp', 'LOLcode', 'LotusScript', 'LScript', 'Lua', 'Make', 'mIRC', 'MXML', 'MySQL', 'NSIS', 'Objective C', 'OCaml', 'OpenOffice BASIC', 'Oracle 8 & 11 SQL', 'Pascal', 'Perl', 'PHP', 'Pixel Bender', 'PL/SQL', 'POV-Ray', 'PowerShell', 'Progress (OpenEdge ABL)', 'Prolog', 'ProvideX', 'Python', 'Q(uick)BASIC', 'robots.txt', 'Ruby', 'Ruby on Rails', 'SAS', 'Scala', 'Scheme', 'Scilab', 'SDLBasic', 'Smalltalk', 'Smarty', 'SQL', 'T-SQL', 'TCL', 'thinBasic', 'TypoScript', 'Uno IDL', 'VB.NET', 'Verilog', 'VHDL', 'VIM Script', 'Visual BASIC', 'Visual Fox Pro', 'Visual Prolog', 'Whitespace', 'Winbatch', 'Windows Registry Files', 'X++', 'XML', 'Xorg.conf'],
    #     help="Set the development language for the paste (default: 'text')")
    g2.add_argument(
        '-U', '--p-user', metavar='NAME', default=prog,
        help="Set alphanumeric paste author (default: '{0}')".format(prog))
    # g2.add_argument(
    #     '--p-password', metavar='PASSWD',
    #     help="Set password string to protect paste")
    # g2.add_argument(
    #     '--p-public', dest='p_private', default='yes', action='store_const', const='no',
    #     help="Set paste to be publicly-discoverable")
    g2.add_argument(
        '-E', '--p-expire', metavar='DAYS', nargs='?', const=2, default=28, type=int,
        help="Set time in days after which paste will be deleted (defaults to '28'; specify '0' to disable expiration; DAYS defaults to '2' if option is used but DAYS is omitted)")
    # g2.add_argument(
    #     '--p-project', metavar='PROJECT',
    #     help="Associate paste with a project")
    g2.add_argument(
        '-h', dest='showUsage', action='store_true',
        help="Show short usage summary and exit")
    g2.add_argument(
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
    o.searchQuery = ''
    if o.q_before:
        o.searchQuery += '&before={0}'.format(o.q_before)
    if o.q_after:
        o.searchQuery += '&after={0}'.format(o.q_after)
    if o.q_bug:
        o.searchQuery += '&bug={0}'.format(o.q_bug)
    if o.q_advisory:
        o.searchQuery += '&advisory={0}'.format(o.q_advisory)
    if o.q_severity:
        o.searchQuery += '&severity={0}'.format(o.q_severity)
    if o.q_package:
        o.searchQuery += '&package={0}'.format(o.q_package)
    if o.q_cwe:
        o.searchQuery += '&cwe={0}'.format(o.q_cwe)
    if o.q_cvss:
        o.searchQuery += '&cvss_score={0}'.format(o.q_cvss)
    if o.q_cvss3:
        o.searchQuery += '&cvss3_score={0}'.format(o.q_cvss3)
    if o.q_raw:
        o.searchQuery += '&{0}'.format(o.q_raw)
    if len(o.cves) == 1 and not o.cves[0].startswith('CVE-'):
        o.showUsage = True
    if o.showUsage or not (len(o.searchQuery) or o.cves):
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


    def __init__(self, fields='threat_severity,public_date,bugzilla,affected_release,package_state',
                 printUrls=False, rawOutput=False, pastebin=False, onlyCount=False, verbose=False, wrapWidth=1):
        """Initialize class settings."""
        self.rhsda = RedHatSecDataApiClient(verbose)
        if len(fields):
            self.desiredFields = fields.split(",")
        else:
            self.desiredFields = []
        self.printUrls = printUrls
        self.rawOutput = rawOutput
        self.output = ""
        if pastebin:
            self.Print = self.paste_printer
        self.onlyCount = onlyCount
        self.cveCount = 0
        if wrapWidth == 1:
            wrapWidth = self.get_terminal_width() - 2
        if wrapWidth:
            self.w = textwrap.TextWrapper(width=wrapWidth, initial_indent="   ", subsequent_indent="   ", replace_whitespace=False)
        else:
            self.w = 0

    def Print(self, text):
        """Print text to stdout."""
        print(text, end="")

    def paste_printer(self, text):
        """Append text to buffer for later pastebin."""
        self.output += text

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
        print("Search query results found: {0}".format(len(result)), file=stderr)
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
        try:
            requrl, j = self.rhsda.get_cve(cve)
        except requests.exceptions.ConnectionError as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            err_print_support_urls()
            exit(1)
        except requests.exceptions.HTTPError as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            if not self.onlyCount:
                self.Print("{0}\n Not present in Red Hat CVE database\n".format(cve))
                if cve.startswith("CVE-"):
                    self.Print(" Try https://cve.mitre.org/cgi-bin/cvename.cgi?name={0}\n\n".format(cve))
            return
        except requests.exceptions.RequestException as e:
            print("{0}: {1}".format(prog, e), file=stderr)
            err_print_support_urls()
            exit(1)

        # If --count was used, done
        if self.onlyCount:
            self.cveCount += 1
            return

        # If --json was used, done
        if self.rawOutput:
            self.Print(jprint(j, False) + "\n")
            return

        # CVE name always printed
        name = ""
        if cve != j['name']:
            name = " [{0}]".format(j['name'])
        url = ""
        if self.printUrls:
            url = " (https://access.redhat.com/security/cve/{0})".format(cve)
        self.Print("{0}{1}{2}\n".format(cve, name, url))

        # If --fields='' was used, done
        if not self.desiredFields:
            return

        if self._check_field('threat_severity', j):
            url = ""
            if self.printUrls:
                url = " (https://access.redhat.com/security/updates/classification)"
            self.Print("  IMPACT:  {0}{1}\n".format(j['threat_severity'], url))

        if self._check_field('public_date', j):
            self.Print("  DATE:  {0}\n".format(j['public_date'].split("T")[0]))

        if self._check_field('iava', j):
            self.Print("  IAVA:")
            if self.printUrls:
                self.Print("\n")
                iavas = j['iava'].split(",")
                for i in iavas:
                    i = i.strip()
                    url = " (https://access.redhat.com/labs/iavmmapper/api/iava/{0})".format(i)
                    self.Print("   {0}{1}\n".format(i, url))
            else:
                self.Print("  {0}\n".format(j['iava']))

        if self._check_field('cwe', j):
            self.Print("  CWE:  {0}".format(j['cwe']))
            if self.printUrls:
                cwes = re.findall("CWE-[0-9]+", j['cwe'])
                if len(cwes) == 1:
                    self.Print(" (http://cwe.mitre.org/data/definitions/{0}.html)\n".format(cwes[0].lstrip("CWE-")))
                else:
                    self.Print("\n")
                    for c in cwes:
                        self.Print("   http://cwe.mitre.org/data/definitions/{0}.html\n".format(c.lstrip("CWE-")))
            else:
                self.Print("\n")

        if self._check_field('cvss', j):
            cvss_scoring_vector = j['cvss']['cvss_scoring_vector']
            if self.printUrls:
                cvss_scoring_vector = "http://nvd.nist.gov/cvss.cfm?version=2&vector={0}".format(cvss_scoring_vector)
            self.Print("  CVSS:  {0} ({1})\n".format(j['cvss']['cvss_base_score'], cvss_scoring_vector))

        if self._check_field('cvss3', j):
            cvss3_scoring_vector = j['cvss3']['cvss3_scoring_vector']
            if self.printUrls:
                cvss3_scoring_vector = "https://www.first.org/cvss/calculator/3.0#{0}".format(cvss3_scoring_vector)
            self.Print("  CVSS3:  {0} ({1})\n".format(j['cvss3']['cvss3_base_score'], cvss3_scoring_vector))

        if 'bugzilla' in self.desiredFields:
            if j.has_key('bugzilla'):
                if self.printUrls:
                    bug = j['bugzilla']['url']
                else:
                    bug = j['bugzilla']['id']
                self.Print("  BUGZILLA:  {0}\n".format(bug))
            else:
                self.Print("  BUGZILLA:  No Bugzilla data\n")
                self.Print("   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy\n")

        if self._check_field('acknowledgement', j):
            self.Print("  ACKNOWLEDGEMENT:  {0}\n".format(self._stripjoin(j['acknowledgement'])))

        if self._check_field('details', j):
            self.Print("  DETAILS:  {0}\n".format(self._stripjoin(j['details'])))

        if self._check_field('statement', j):
            self.Print("  STATEMENT:  {0}\n".format(self._stripjoin(j['statement'])))

        if self._check_field('mitigation', j):
            self.Print("  MITIGATION:  {0}\n".format(self._stripjoin(j['mitigation'])))

        if self._check_field('upstream_fix', j):
            self.Print("  UPSTREAM_FIX:  {0}\n".format(j['upstream_fix']))

        if self._check_field('references', j):
            self.Print("  REFERENCES:{0}\n".format(self._stripjoin(j['references'], oneLineEach=True)))

        if self._check_field('affected_release', j):
            self.Print("  AFFECTED_RELEASE (ERRATA):\n")
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
                self.Print("   {0}{1}: {2}\n".format(release['product_name'], package, advisory))

        if self._check_field('package_state', j):
            self.Print("  PACKAGE_STATE:\n")
            package_state = j['package_state']
            if isinstance(package_state, dict):
                # When there's only one, it doesn't show up in a list
                package_state = [package_state]
            for state in package_state:
                package_name = ""
                if state.has_key('package_name'):
                    package_name = " [{0}]".format(state['package_name'])
                self.Print("   {2}: {0}{1}\n".format(state['product_name'], package_name, state['fix_state']))

        # Add one final newline to the end
        self.Print("\n")


def main(opts):
    a = RHSecApiParse(opts.fields, opts.printUrls, opts.json, opts.pastebin, opts.count, opts.verbose, opts.wrapWidth)
    if len(opts.searchQuery):
        result = a.search_query(opts.searchQuery)
        if opts.extract_search:
            if result:
                for i in result:
                    opts.cves.append(i['CVE'])
        elif not opts.count:
            a.Print(jprint(result, False))
            a.Print("\n")
    if opts.cves:
        for cve in opts.cves:
            a.print_cve(cve)
        if opts.count:
            print("Valid CVE results found: {0} of {1}".format(a.cveCount, len(opts.cves)), file=stderr)
            print("Invalid CVE queries: {0} of {1}".format(len(opts.cves)-a.cveCount, len(opts.cves)), file=stderr)
    if opts.pastebin:
        opts.p_lang = 'text'
        if opts.json or not opts.cves:
            opts.p_lang = 'Python'
        opts.p_password = None
        opts.p_private = 'yes'
        opts.p_project = None
        fpaste_it(a.output, opts.p_lang, opts.p_user, opts.p_password, opts.p_private, opts.p_expire, opts.p_project)


if __name__ == "__main__":
    try:
        opts = parse_args()
        main(opts)
    except KeyboardInterrupt:
        print("\nReceived KeyboardInterrupt. Exiting.")
        exit()
else:
    a = RedHatSecDataApiClient(True)