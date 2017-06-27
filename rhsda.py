#!/usr/bin/python2
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

# Modules from standard library
from __future__ import print_function
import requests
import logging
import sys
import re
import textwrap, fcntl, termios, struct
import json
import signal
import copy_reg
import types
import multiprocessing.dummy as multiprocessing
from argparse import Namespace


# Logging
logging.addLevelName(25, 'NOTICE')
consolehandler = logging.StreamHandler()
consolehandler.setLevel('DEBUG')
consolehandler.setFormatter(logging.Formatter("[%(levelname)-7s] %(name)s: %(message)s"))
logger = logging.getLogger('rhsda')
logger.setLevel('NOTICE')
logger.addHandler(consolehandler)


# Establish cveFields namespace
cveFields = Namespace()
# All supported API-provided CVE fields
cveFields.all = [
    'threat_severity',
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
# The few text-heavy fields
cveFields.not_most = [
    'acknowledgement',
    'details',
    'statement',
    'mitigation',
    'references',
    ]
# All fields except the above
cveFields.most = list(cveFields.all)
for f in cveFields.not_most:
    cveFields.most.remove(f)
del(f)
# Simple set of most important fields
cveFields.base = [
    'threat_severity',
    'public_date',
    'bugzilla',
    'affected_release',
    'package_state',
    ]
# Aliases to make life easier
cveFields.aliases = {
    'severity': 'threat_severity',
    'date': 'public_date',
    'fixed_releases': 'affected_release',
    'fixed': 'affected_release',
    'releases': 'affected_release',
    'fix_states': 'package_state',
    'states': 'package_state',
    }
# Printable mapping of aliases
cveFields.aliases_printable = [
    "threat_severity → severity",
    "public_date → date",
    "affected_release → fixed_releases or fixed or releases",
    "package_state → fix_states or states",
    ]
# A list of all fields + all aliases
cveFields.all_plus_aliases = list(cveFields.all)
cveFields.all_plus_aliases.extend([k for k in cveFields.aliases])
del(k)


# Regex to match a CVE id string
cve_regex_string = 'CVE-[0-9]{4}-[0-9]{4,}'
cve_regex = re.compile(cve_regex_string, re.IGNORECASE)


# The following function & copy_reg.pickle() call make it possible for pickle to serialize class functions
# This is critical to allow multiprocessing.Pool.map_async() to work as desired
# See: http://stackoverflow.com/a/19861595
def _reduce_method(m):
    if m.__self__ is None:
        return getattr, (m.__class__, m.__func__.__name__)
    else:
        return getattr, (m.__self__, m.__func__.__name__)

copy_reg.pickle(types.MethodType, _reduce_method)


# Set default number of worker threads
if multiprocessing.cpu_count() <= 2:
    numThreadsDefault = 4
else:
    numThreadsDefault = multiprocessing.cpu_count() * 2


def jprint(jsoninput):
    """Pretty-print jsoninput."""
    return json.dumps(jsoninput, sort_keys=True, indent=2) + "\n"


def extract_cves_from_input(obj, descriptiveNoun=None):
    """Use case-insensitive regex to extract CVE ids from input object.

    *obj* can be a list, a file, or a string.

    A list of CVEs is returned.
    """
    # Array to store found CVEs
    found = []
    if obj == sys.stdin:
        descriptiveNoun = "stdin"
    elif not descriptiveNoun:
        descriptiveNoun = "input"
        if isinstance(obj, str):
            obj = obj.splitlines()
    for line in obj:
        # Iterate over each line adding the returned list to our found list
        found.extend(cve_regex.findall(line))
    if found:
        originalCount = len(found)
        # Converting to a set removes duplicates
        found = list(set([x.upper() for x in found]))
        dupesRemoved = originalCount - len(found)
        if dupesRemoved:
            dupes = "; {0} duplicates removed".format(dupesRemoved)
        else:
            dupes = ""
        logger.log(25, "Found {0} CVEs on {1}{2}".format(len(found), descriptiveNoun, dupes))
        return found
    else:
        logger.warning("No CVEs (matching regex: '{0}') found on {1}".format(cve_regex_string, descriptiveNoun))
        return []


class ApiClient:
    """Portable object to interface with the Red Hat Security Data API.

    https://access.redhat.com/documentation/en/red-hat-security-data-api/
    """

    def __init__(self, logLevel='notice'):
        self.cfg = Namespace()
        self.cfg.apiUrl = 'https://access.redhat.com/labs/securitydataapi'
        logger.setLevel(logLevel.upper())

    def _get_terminal_width(self):
        h, w, hp, wp = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('HHHH', 0, 0, 0, 0)))
        return w

    def __validate_data_type(self, dT):
        dataTypes = ['cvrf', 'cve', 'oval', 'iava']
        if dT not in dataTypes:
            raise ValueError("Invalid data type ('{0}') requested; should be one of: {1}".format(dT, ", ".join(dataTypes)))

    def __validate_out_format(self, oF):
        outFormats = ['json', 'xml']
        if oF not in outFormats:
            raise ValueError("Invalid outFormat type ('{0}') requested; should be one of: {1}".format(oF, ", ".join(outFormats)))

    def __get(self, url, params={}):
        url = self.cfg.apiUrl + url
        u = ""
        if params:
            for k in params:
                if params[k]:
                    u += "&{0}={1}".format(k, params[k])
            u = u.replace("&", "?", 1)
        logger.info("Getting {0}{1}".format(url, u))
        try:
            r = requests.get(url, params=params)
        except requests.exceptions.ConnectionError as e:
            logger.error(e)
            raise
        except requests.exceptions.RequestException as e:
            logger.error(e)
            raise
        baseurl = r.url.split("/")[-1]
        if not baseurl:
            baseurl = r.url.split("/")[-2]
        logger.debug("Return '.../{0}': Status {1}, Content-Type {2}".format(baseurl, r.status_code, r.headers['Content-Type'].split(";")[0]))
        r.raise_for_status()
        if 'application/json' in r.headers['Content-Type']:
            return r.json()
        else:
            return r.content

    def _find(self, dataType, params, outFormat):
        self.__validate_data_type(dataType)
        self.__validate_out_format(outFormat)
        url = '/{0}.{1}'.format(dataType, outFormat)
        if isinstance(params, dict):
            result = self.__get(url, params)
        elif params:
            result = self.__get(url + '?' + params)
        else:
            result = self.__get(url)
        if isinstance(result, list):
            logger.log(25, "{0} {1}s found with search query".format(len(result), dataType.upper()))
        return result

    def _retrieve(self, dataType, query, outFormat):
        self.__validate_data_type(dataType)
        self.__validate_out_format(outFormat)
        url = '/{0}/{1}.{2}'.format(dataType, query, outFormat)
        return self.__get(url)

    def find_cvrfs(self, params=None, outFormat='json',
                   before=None, after=None, bug=None, cve=None, severity=None, package=None,
                   page=None, per_page=None):
        """Find CVRF documents by recent or attributes.

        Provides an index to recent CVRF documents when no parameters are passed.
        Each list item is a convenience object with minimal attributes.
        Use parameters to narrow down results.

        With *outFormat* of "json", returns JSON object.
        With *outFormat* of "xml", returns unformatted XML as string.
        If *params* dict is passed, additional parameters are ignored.
        """
        if not params:
            params = {
                'before': before,
                'after': after,
                'bug': bug,
                'cve': cve,
                'severity': severity,
                'package': package,
                'page': page,
                'per_page': per_page,
                }
        return self._find('cvrf', params, outFormat)

    def find_cves(self, params=None, outFormat='json',
                  before=None, after=None, bug=None, advisory=None, severity=None,
                  product=None, package=None, cwe=None, cvss_score=None, cvss3_score=None,
                  page=None, per_page=None):
        """Find CVEs by recent or attributes.

        Provides an index to recent CVEs when no parameters are passed.
        Each list item is a convenience object with minimal attributes.
        Use parameters to narrow down results.
 
        With *outFormat* of "json", returns JSON object.
        With *outFormat* of "xml", returns unformatted XML as string.
        If *params* dict is passed, additional parameters are ignored.
        """
        if not params:
            params = {
                'before': before,
                'after': after,
                'bug': bug,
                'advisory': advisory,
                'severity': severity,
                'product': product,
                'package': package,
                'cwe': cwe,
                'cvss_score': cvss_score,
                'cvss3_score': cvss3_score,
                'page': page,
                'per_page': per_page,
                }
        return self._find('cve', params, outFormat)

    def find_ovals(self, params=None, outFormat='json',
                   before=None, after=None, bug=None, cve=None, severity=None,
                   page=None, per_page=None):
        """Find OVAL definitions by recent or attributes.

        Provides an index to recent OVAL definitions when no parameters are passed.
        Each list item is a convenience object with minimal attributes.
        Use parameters to narrow down results.

        With *outFormat* of "json", returns JSON object.
        With *outFormat* of "xml", returns unformatted XML as string.
        If *params* dict is passed, additional parameters are ignored.
        """
        if not params:
            params = {
                'before': before,
                'after': after,
                'bug': bug,
                'cve': cve,
                'severity': severity,
                'page': page,
                'per_page': per_page,
                }
        return self._find('oval', params, outFormat)

    def find_iavas(self, params=None, outFormat='json',
                   number=None, severity=None,
                   page=None, per_page=None):
        """Find IAVA notices by recent or attributes.

        Provides an index to recent IAVA notices when no parameters are passed.
        Each list item is a convenience object with minimal attributes.
        Use parameters to narrow down results.

        With *outFormat* of "json", returns JSON object.
        With *outFormat* of "xml", returns unformatted XML as string.
        If *params* dict is passed, additional parameters are ignored.
        """
        if not params:
            params = {
                'number': number,
                'severity': severity,
                'page': page,
                'per_page': per_page,
                }
        return self._find('iava', params, outFormat)

    def get_cvrf(self, rhsa, outFormat='json'):
        """Retrieve CVRF details for an RHSA."""
        return self._retrieve('cvrf', rhsa, outFormat)

    def get_cvrf_oval(self, rhsa, outFormat='json'):
        """Retrieve CVRF-OVAL details for an RHSA."""
        return self._retrieve('cvrf', '{0}/oval'.format(rhsa), outFormat)

    def get_cve(self, cve, outFormat='json'):
        """Retrieve full details of a CVE."""
        return self._retrieve('cve', cve, outFormat)

    def get_oval(self, rhsa, outFormat='json'):
        """Retrieve OVAL details for an RHSA."""
        return self._retrieve('oval', rhsa, outFormat)

    def get_iava(self, iava, outFormat='json'):
        """Retrieve notice details for an IAVA."""
        return self._retrieve('iava', iava, outFormat)

    def __stripjoin(self, input, oneLineEach=False):
        """Strip whitespace from input or input list."""
        text = ""
        if isinstance(input, list):
            if oneLineEach:
                text = "\n".join(input).encode('utf-8').strip()
            else:
                text = "  ".join(input).encode('utf-8').strip()
        else:
            text = input.encode('utf-8').strip()
        if oneLineEach:
            text = "\n" + text
            text = re.sub(r"\n[\n\s]*", "\n   ", text)
        else:
            text = re.sub(r"\n[\n\s]*", "  ", text)
            if self.wrapper:
                text = "\n" + "\n".join(self.wrapper.wrap(text))
        return text

    def __check_field(self, field, jsoninput):
        """Return True if field is desired and exists in jsoninput."""
        if field in self.cfg.desiredFields and field in jsoninput:
            return True
        return False

    def _get_and_parse_cve(self, cve):
        """Generate a plaintext representation of a CVE.

        This is designed with only one argument in order to allow being used as a worker
        with multiprocessing.Pool.map_async().

        Various printing operations in this method are conditional upon (or are tweaked
        by) the values in the self.cfg namespace as set in parent meth self.mget_cves().
        """
        # Output array:
        out = []
        try:
            # Store json
            J = self.get_cve(cve)
        except requests.exceptions.HTTPError as e:
            # CVE not in RH CVE DB
            logger.info(e)
            if self.cfg.product or self.cfg.onlyCount or self.cfg.outFormat.startswith('json'):
                return False, ""
            else:
                out.append("{0}\n  Not present in Red Hat CVE database".format(cve))
                if cve.startswith("CVE-"):
                    out.append("  Try https://cve.mitre.org/cgi-bin/cvename.cgi?name={0}".format(cve))
                out.append("")
                return False, "\n".join(out)
        # If json output requested
        if self.cfg.outFormat.startswith('json'):
            return True, J
        # CVE ID
        name = ""
        if cve != J['name']:
            name = " [{0}]".format(J['name'])
        u = ""
        if self.cfg.urls:
            u = " (https://access.redhat.com/security/cve/{0})".format(cve)
        out.append("{0}{1}{2}".format(cve, name, u))
        # SEVERITY
        if self.__check_field('threat_severity', J):
            u = ""
            if self.cfg.urls:
                u = " (https://access.redhat.com/security/updates/classification)"
            out.append("  SEVERITY : {0} Impact{1}".format(J['threat_severity'], u))
        # PUBLIC_DATE
        if self.__check_field('public_date', J):
            out.append("  DATE     : {0}".format(J['public_date'].split("T")[0]))
        # IAVA
        if self.__check_field('iava', J):
            out.append("  IAVA     : {0}".format(J['iava']))
        # CWE ID
        if self.__check_field('cwe', J):
            out.append("  CWE      : {0}".format(J['cwe']))
            if self.cfg.urls:
                cwes = re.findall("CWE-[0-9]+", J['cwe'])
                if len(cwes) == 1:
                    out[-1] += " (http://cwe.mitre.org/data/definitions/{0}.html)".format(cwes[0].lstrip("CWE-"))
                else:
                    for c in cwes:
                        out.append("             (http://cwe.mitre.org/data/definitions/{0}.html)".format(c.lstrip("CWE-")))
        # CVSS2
        if self.__check_field('cvss', J):
            vector = J['cvss']['cvss_scoring_vector']
            if self.cfg.urls:
                vector = "http://nvd.nist.gov/cvss.cfm?version=2&vector={0}".format(vector)
            out.append("  CVSS     : {0} ({1})".format(J['cvss']['cvss_base_score'], vector))
        # CVSS3
        if self.__check_field('cvss3', J):
            vector = J['cvss3']['cvss3_scoring_vector']
            if self.cfg.urls:
                vector = "https://www.first.org/cvss/calculator/3.0#{0}".format(vector)
            out.append("  CVSS3    : {0} ({1})".format(J['cvss3']['cvss3_base_score'], vector))
        # BUGZILLA
        if 'bugzilla' in self.cfg.desiredFields:
            if 'bugzilla' in J:
                if self.cfg.urls:
                    bug = J['bugzilla']['url']
                else:
                    bug = J['bugzilla']['id']
                out.append("  BUGZILLA : {0}".format(bug))
            else:
                out.append("  BUGZILLA : No Bugzilla data")
                out.append("   Too new or too old? See: https://bugzilla.redhat.com/show_bug.cgi?id=CVE_legacy")
        # ACKNOWLEDGEMENT
        if self.__check_field('acknowledgement', J):
            out.append("  ACKNOWLEDGEMENT :  {0}".format(self.__stripjoin(J['acknowledgement'])))
        # DETAILS
        if self.__check_field('details', J):
            out.append("  DETAILS  : {0}".format(self.__stripjoin(J['details'])))
        # STATEMENT
        if self.__check_field('statement', J):
            out.append("  STATEMENT : {0}".format(self.__stripjoin(J['statement'])))
        # MITIGATION
        if self.__check_field('mitigation', J):
            out.append("  MITIGATION : {0}".format(self.__stripjoin(J['mitigation'])))
        # UPSTREAM FIX
        if self.__check_field('upstream_fix', J):
            out.append("  UPSTREAM_FIX : {0}".format(J['upstream_fix']))
        # REFERENCES
        if self.__check_field('references', J):
            out.append("  REFERENCES :{0}".format(self.__stripjoin(J['references'], oneLineEach=True)))
        # AFFECTED RELEASE
        foundProduct_affected_release = False
        if self.__check_field('affected_release', J):
            if self.cfg.product:
                out.append("  FIXED_RELEASES matching '{0}' :".format(self.cfg.product))
            else:
                out.append("  FIXED_RELEASES :")
            affected_release = J['affected_release']
            if isinstance(affected_release, dict):
                # When there's only one, it doesn't show up in a list
                affected_release = [affected_release]
            for release in affected_release:
                if self.cfg.product:
                    if self.regex_product.search(release['product_name']) or self.regex_product.search(release['cpe']):
                        foundProduct_affected_release = True
                    else:
                        # If product doesn't match spotlight, go to next
                        continue
                pkg = ""
                if 'package' in release:
                    pkg = " [{0}]".format(release['package'])
                advisory = release['advisory']
                if self.cfg.urls:
                    advisory = "https://access.redhat.com/errata/{0}".format(advisory)
                out.append("   {0}:{1} via {2} ({3})".format(release['product_name'], pkg, advisory, release['release_date'].split("T")[0]))
            if self.cfg.product and not foundProduct_affected_release:
                # If nothing found, remove the "FIXED_RELEASES" heading
                out.pop()
        # PACKAGE STATE
        foundProduct_package_state = False
        if self.__check_field('package_state', J):
            if self.cfg.product:
                out.append("  FIX_STATES matching '{0}' :".format(self.cfg.product))
            else:
                out.append("  FIX_STATES :")
            package_state = J['package_state']
            if isinstance(package_state, dict):
                # When there's only one, it doesn't show up in a list
                package_state = [package_state]
            for state in package_state:
                if self.cfg.product:
                    if self.regex_product.search(state['product_name']) or self.regex_product.search(state['cpe']):
                        foundProduct_package_state = True
                    else:
                        # If product doesn't match spotlight, go to next
                        continue
                pkg = ""
                if 'package_name' in state:
                    pkg = " [{0}]".format(state['package_name'])
                out.append("   {0}: {1}{2}".format(state['fix_state'], state['product_name'], pkg))
            if self.cfg.product and not foundProduct_package_state:
                # If nothing found, remove the "FIX_STATES" heading
                out.pop()
        # If searching for product and not found return no output
        if self.cfg.product and not (foundProduct_affected_release or foundProduct_package_state):
            logger.info("Hiding {0} due to negative product match".format(cve))
            return None, ""
        # Return no output if only counting
        if self.cfg.onlyCount:
            return True, ""
        # Add one final newline to the end
        out.append("")
        return True, "\n".join(out)

    def _get_and_parse_iava(self, iava):
        """Generate a plaintext representation of an IAVA.

        This is designed with only one argument in order to allow being used as a worker
        with multiprocessing.Pool.map_async().

        Various printing operations in this method are conditional upon (or are tweaked
        by) the values in the self.cfg namespace as set in parent meth self.mget_iavas().
        """
        # Output array:
        out = []
        try:
            # Store json
            J = self.get_iava(iava)
        except requests.exceptions.HTTPError as e:
            # IAVA not in RH IAVA DB
            logger.info(e)
            if self.cfg.onlyCount or self.cfg.outFormat in ['list', 'json', 'jsonpretty']:
                return False, "", 0
            else:
                return False, "{0}\n  Not present in Red Hat IAVA database\n".format(iava), 0
        numCves = len(J['cvelist'])
        # If json output requested
        if self.cfg.outFormat.startswith('json'):
            return True, J, numCves
        # If CVE list output
        elif self.cfg.outFormat == 'list': 
            return True, J['cvelist'], numCves
        # If onlyCount requested
        elif self.cfg.onlyCount:
            return True, "", numCves
        # IAVA NUMBER
        u = ""
        if self.cfg.urls:
            u = " ({0}/iava?number={1})".format(self.cfg.apiUrl, iava)
        out.append("{0}{1}".format(iava, u))
        # TITLE
        out.append("  TITLE    : {0}".format(J['title']))
        # SEVERITY
        out.append("  SEVERITY : {0}".format(J['severity']))
        # ID
        out.append("  ID       : {0}".format(J['id']))
        # CVELIST
        if J['cvelist']:
            out.append("  CVES     :")
            for cve in J['cvelist']:
                u = ""
                if self.cfg.urls:
                    u = " (https://access.redhat.com/security/cve/{0})".format(cve)
                out.append("   {0}{1}".format(cve, u))
        # Add one final newline to the end
        out.append("")
        return True, "\n".join(out), numCves

    def _set_cve_plaintext_fields(self, desiredFields):
        logger.debug("Requested fields string: '{0}'".format(desiredFields))
        if not desiredFields:
            # Start with all fields if none given
            desiredFields = ','.join(cveFields.all)
        # Lower case
        desiredFields = desiredFields.lower()
        if desiredFields == 'all':
            desiredFields = ','.join(cveFields.all)
        elif desiredFields == 'most':
            desiredFields = ','.join(cveFields.most)
        elif desiredFields == 'base':
            desiredFields = ','.join(cveFields.base)
        # Save starting fields to temporary "fields" list; create postProcessed list
        if desiredFields.startswith('+'):
            fields = desiredFields[1:].split(',')
            postProcessedFields = list(cveFields.base)
        elif desiredFields.startswith('^'):
            fields = desiredFields[1:].split(',')
            postProcessedFields = list(cveFields.all)
        else:
            fields = desiredFields.split(',')
            postProcessedFields = []
        # Iterate over list
        for f in fields:
            # Skip unknown fields
            if f not in cveFields.all_plus_aliases:
                logger.warning("Field '{0}' is not a known field; valid fields:\n{2}".format(f, ", ".join(cveFields.all_plus_aliases)))
                continue
            # Look-up aliases
            if f not in cveFields.all:
                f = cveFields.aliases[f]
            # If using ^/+, remove/add field from/to defaults
            if desiredFields.startswith('^') and f in postProcessedFields:
                postProcessedFields.remove(f)
            elif desiredFields.startswith('+'):
                postProcessedFields.append(f)
            # Otherwise, add to postprocessed list
            else:
                postProcessedFields.append(f)
        logger.debug("Enabled fields: '{0}'".format(", ".join(postProcessedFields)))
        self.cfg.desiredFields = postProcessedFields

    def _set_cve_plaintext_product(self, product):
        self.cfg.product = product
        if product:
            self.regex_product = re.compile(product, re.IGNORECASE)
        else:
            self.regex_product = None

    def _set_cve_plaintext_width(self, wrapWidth):
        if wrapWidth == 1:
            if sys.stdin.isatty():
                wrapWidth = self._get_terminal_width() - 2
            else:
                logger.warning("Stdin redirection suppresses term-width auto-detection; setting WIDTH to 70")
                wrapWidth = 70
        if wrapWidth:
            self.wrapper = textwrap.TextWrapper(width=wrapWidth, initial_indent="   ", subsequent_indent="   ", replace_whitespace=False)
        else:
            self.wrapper = 0
        logger.debug("Set wrapWidth to '{0}'".format(wrapWidth))

    def mget_cves(self, cves, numThreads=0, onlyCount=False, outFormat='plaintext',
                  urls=False, fields='ALL', wrapWidth=70, product=None, timeout=300):
        """Use multi-threading to lookup a list of CVEs and return text output.

        *cves*:       A list of CVE ids or a str/file obj from which to regex CVE ids
        *numThreads*: Number of concurrent worker threads; 0 == CPUs*2
        *onlyCount*:  Whether to exit after simply logging number of valid/invalid CVEs
        *outFormat*:  Control output format ("plaintext", "json", or "jsonpretty")
        *urls*:       Whether to add extra URLs to certain fields
        *fields*:     Customize which fields are displayed by passing comma-sep string
        *wrapWidth*:  Width for long fields; 1 auto-detects based on terminal size
        *product*:    Restrict display of CVEs based on product-matching regex
        *timeout*:    Total ammount of time to wait for all CVEs to be retrieved

        ON *CVES*:

        If *cves* is a list, each item in the list will be retrieved as a CVE.
        If *cves* is a string or file object, it will be regex-parsed line by line and
        all CVE ids will be extracted into a list.
        In all cases, character-case is irrelevant.

        ON *OUTFORMAT*:

        Setting to "plaintext" returns str object containing formatted output.
        Setting to "json" returns list object (i.e., original JSON)
        Setting to "jsonpretty" returns str object containing prettified JSON

        ON *FIELDS*:

        librhsecapi.cveFields.all is a list obj of supported fields, i.e.:
            threat_severity, public_date, iava, cwe, cvss, cvss3, bugzilla,
            acknowledgement, details, statement, mitigation, upstream_fix, references,
            affected_release, package_state

        librhsecapi.cveFields.most is a list obj that excludes text-heavy fields, like:
            acknowledgement, details, statement, mitigation, references

        librhsecapi.cveFields.base is a list obj of the most important fields, i.e.:
            threat_severity, public_date, bugzilla, affected_release, package_state

        There is a group-alias for each of these, so you can do:
            fields="ALL"
            fields="MOST"
            fields="BASE"

        Also note that some friendly aliases are supported, e.g.:
            threat_severity → severity
            public_date → date
            affected_release → fixed_releases or fixed or releases
            package_state → fix_states or states

        Note that the *fields* string can be prepended with "+" or "^" to signify
        adding to cveFields.base or removing from cveFields.all, e.g.:
            fields="+cvss,cwe,statement"
            fields="^releases,mitigation"

        Finally: *fields* is case-insensitive.
        """
        if outFormat not in ['plaintext', 'json', 'jsonpretty']:
            raise ValueError("Invalid outFormat ('{0}') requested; should be one of: 'plaintext', 'json', 'jsonpretty'".format(outFormat))
        if isinstance(cves, str) or isinstance(cves, file):
            cves = extract_cves_from_input(cves)
        elif not isinstance(cves, list):
            raise ValueError("Invalid 'cves=' argument input; must be list, string, or file obj")
        if not len(cves):
            if outFormat in ['plaintext', 'jsonpretty']:
                return ""
            else:
                return []
        # Configure threads
        if not numThreads:
            numThreads = numThreadsDefault
        # Lower threads for small work-loads 
        if numThreads > len(cves):
            numThreads = len(cves)
        logger.info("Using {0} worker threads".format(numThreads))
        # Set cfg directives for our worker
        self.cfg.onlyCount = onlyCount
        self.cfg.urls = urls
        self.cfg.outFormat = outFormat
        self._set_cve_plaintext_width(wrapWidth)
        self._set_cve_plaintext_fields(fields)
        self._set_cve_plaintext_product(product)
        # Disable sigint before starting process pool
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = multiprocessing.Pool(processes=numThreads)
        # Re-enable receipt of sigint
        signal.signal(signal.SIGINT, original_sigint_handler)
        # Allow cancelling with Ctrl-c
        try:
            p = pool.map_async(self._get_and_parse_cve, cves)
            # Need to specify timeout; see: http://stackoverflow.com/a/35134329
            results = p.get(timeout=timeout)
        except KeyboardInterrupt:
            logger.error("Received KeyboardInterrupt; terminating worker threads")
            pool.terminate()
            raise
        else:
            pool.close()
        pool.join()
        successValues, cveOutput = zip(*results)
        n_total = len(cves)
        n_hidden = successValues.count(None)
        n_valid = successValues.count(True)
        logger.log(25, "Valid Red Hat CVE results retrieved: {0} of {1}".format(n_valid + n_hidden, n_total))
        if product:
            logger.log(25, "Results matching spotlight-product option: {0} of {1}".format(n_valid, n_total))
        if onlyCount:
            return
        if outFormat == 'plaintext':
            # Remove all blank entries (created when spotlight-product hides a CVE)
            cveOutput = list(cveOutput)
            while 1:
                try:
                    cveOutput.remove("")
                except ValueError:
                    break
            return "\n".join(cveOutput)
        elif outFormat == 'json':
            return cveOutput
        elif outFormat == 'jsonpretty':
            return jprint(cveOutput)

    def mget_iavas(self, iavas, numThreads=0, onlyCount=False, outFormat='plaintext',
                   urls=False, timeout=300):
        """Use multi-threading to lookup a list of IAVAs and return text output.

        *iavas*:      A list of IAVA ids
        *numThreads*: Number of concurrent worker threads; 0 == CPUs*2
        *onlyCount*:  Whether to exit after simply logging number of valid/invalid CVEs
        *outFormat*:  Control output format ("list", "plaintext", "json", or "jsonpretty")
        *urls*:       Whether to add extra URLs to certain fields
        *timeout*:    Total ammount of time to wait for all CVEs to be retrieved

        ON *OUTFORMAT*:

        Setting to "list" returns list object containing ONLY CVE ids.
        Setting to "plaintext" returns str object containing formatted output.
        Setting to "json" returns list object (i.e., original JSON)
        Setting to "jsonpretty" returns str object containing prettified JSON
        """
        if outFormat not in ['list', 'plaintext', 'json', 'jsonpretty']:
            raise ValueError("Invalid outFormat ('{0}') requested; should be one of: 'list', 'plaintext', 'json', 'jsonpretty'".format(outFormat))
        if not isinstance(iavas, list):
            raise ValueError("Invalid 'iavas=' argument input; must be list obj")
        # Configure threads
        if not numThreads:
            numThreads = numThreadsDefault
        # Lower threads for small work-loads 
        if numThreads > len(iavas):
            numThreads = len(iavas)
        logger.info("Using {0} worker threads".format(numThreads))
        # Set cfg directives for our worker
        self.cfg.onlyCount = onlyCount
        self.cfg.outFormat = outFormat
        self.cfg.urls = urls
        # Disable sigint before starting process pool
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = multiprocessing.Pool(processes=numThreads)
        # Re-enable receipt of sigint
        signal.signal(signal.SIGINT, original_sigint_handler)
        # Allow cancelling with Ctrl-c
        try:
            p = pool.map_async(self._get_and_parse_iava, iavas)
            # Need to specify timeout; see: http://stackoverflow.com/a/35134329
            results = p.get(timeout=timeout)
        except KeyboardInterrupt:
            logger.error("Received KeyboardInterrupt; terminating worker threads")
            pool.terminate()
            raise
        else:
            pool.close()
        pool.join()
        successValues, iavaOutput, numCves = zip(*results)
        n_total = len(iavas)
        n_hidden = successValues.count(None)
        n_valid = successValues.count(True)
        logger.log(25, "Valid Red Hat IAVA results retrieved: {0} of {1}".format(n_valid + n_hidden, n_total))
        if sum(numCves):
            logger.log(25, "Number of CVEs mapped from retrieved IAVAs: {0}".format(sum(numCves)))
        if outFormat == 'list':
            cves = []
            for cvelist in iavaOutput:
                cves.extend(cvelist)
            return cves
        elif onlyCount:
            return
        if outFormat == 'plaintext':
            return "\n".join(iavaOutput)
        elif outFormat == 'json':
            return iavaOutput
        elif outFormat == 'jsonpretty':
            return jprint(iavaOutput)

    def cve_search_query(self, params, outFormat='list', urls=False):
        """Perform a CVE search query.

        ON *OUTFORMAT*:

        Setting to "list" returns list of found CVE ids.
        Setting to "plaintext" returns str object containing new-line separated CVE ids.
        Setting to "json" returns list object containing original JSON.
        Setting to "jsonpretty" returns str object containing prettified JSON.
        """
        if outFormat not in ['list', 'plaintext', 'json', 'jsonpretty']:
            raise ValueError("Invalid outFormat ('{0}') requested; should be one of: 'list', 'plaintext', 'json', 'jsonpretty'".format(outFormat))
        result = self.find_cves(params)
        if outFormat == 'json':
            return result
        if outFormat == 'jsonpretty':
            return jprint(result)
        if outFormat == 'list':
            cves = []
            for i in result:
                cves.append(i['CVE'])
            return cves
        if outFormat == 'plaintext':
            rows = []
            rows.append(["CVE ID", "PUB DATE", "BUGZILLA", "SEVERITY", "CVSS2", "CVSS3",  "RHSAS", "PKGS"])
            for i in result:
                date = ""
                if 'public_date' in i and i['public_date'] is not None:
                    date = i['public_date'].split("T")[0]
                bz = ""
                if urls:
                    cve = "https://access.redhat.com/security/cve/{0}".format(i['CVE'])
                    if 'bugzilla' in i and i['bugzilla'] is not None:
                        bz = "https://bugzilla.redhat.com/show_bug.cgi?id={0}".format(i['bugzilla'])
                else:
                    cve = i['CVE']
                    if 'bugzilla' in i and i['bugzilla'] is not None:
                        bz = i['bugzilla']
                severity = ""
                if 'severity' in i and i['severity'] is not None:
                    severity = i['severity']
                cvss2 = ""
                if 'cvss_score' in i and i['cvss_score'] is not None:
                    cvss2 = str(i['cvss_score'])
                cvss3 = ""
                if 'cvss3_score' in i and i['cvss3_score'] is not None:
                    cvss3 = str(i['cvss3_score'])
                rhsas = ""
                if 'advisories' in i and i['advisories'] is not None:
                    rhsas = "{0: >2}".format(len(i['advisories']))
                pkgs = ""
                if 'affected_packages' in i and i['affected_packages'] is not None:
                    pkgs = "{0: >2}".format(len(i['affected_packages']))
                line = [cve, date, bz, severity, cvss2, cvss3, rhsas, pkgs] 
                rows.append(line)
            return self._columnize(rows, sep="  ")

    def _columnize(self, rows, sep="  "):
        """Columnize (a la column -t) input list of lists, returning string.
        Credit: http://stackoverflow.com/a/12065663
        """
        widths = [ max(map(len, col)) for col in zip(*rows) ]
        output = []
        for row in rows:
            output.append(sep.join((val.ljust(width) for val,width in zip(row, widths))))
        return "\n".join(output)


if __name__ == "__main__":
    a = ApiClient('info')
    print(a.mget_cves(sys.stdin), end="")
