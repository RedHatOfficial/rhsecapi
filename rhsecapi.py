#!/usr/bin/python2
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK
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
import argparse
import requests
import sys
import logging
import rhsda
from os import path

# Optional argcomplete module
haveArgcomplete = False
if not (path.isfile(path.expanduser('~/.rhsecapi-no-argcomplete')) or path.isfile('/etc/rhsecapi-no-argcomplete')):
    try:
        import argcomplete
        haveArgcomplete = True
    except:
        print("Missing optional python module: argcomplete\n\n"
              "  To enable bash auto-magic tab-completion, install it:\n"
              "    yum/dnf install python-pip\n"
              "    pip install argcomplete\n"
              "    activate-global-python-argcomplete\n"
              "    (Open new shell)\n\n"
              "  To skip using argcomplete AND disable future printing of this message:\n"
              "    touch ~/.rhsecapi-no-argcomplete\n"
              "      OR\n"
              "    touch /etc/rhsecapi-no-argcomplete\n", file=sys.stderr)

# Globals
prog = 'rhsecapi'
vers = {}
vers['version'] = '1.0.1'
vers['date'] = '2017/06/27'


# Logging
logging.addLevelName(25, 'NOTICE')
consolehandler = logging.StreamHandler()
consolehandler.setLevel('DEBUG')
consolehandler.setFormatter(logging.Formatter("[%(levelname)-7s] %(name)s: %(message)s"))
logger = logging.getLogger('rhsecapi')
logger.setLevel('NOTICE')
logger.addHandler(consolehandler)


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
        raise ValueError("Fedora Pastebin client WARN: paste size ({0:.1f} KiB) too large (max size: 512 KiB)".format(pasteSizeKiB))
    # Print status, then connect
    logger.log(25, "Fedora Pastebin client uploading {0:.1f} KiB...".format(pasteSizeKiB))
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
        raise ValueError("Fedora Pastebin client ERROR: Didn't receive expected JSON response (saved to '{0}' for debugging)".format(tmp.name))
    # Error keys adapted from Jason Farrell's fpaste
    if j.has_key('error'):
        err = j['error']
        if err == 'err_spamguard_php':
            raise ValueError("Fedora Pastebin server ERROR: Poster's IP rejected as malicious")
        elif err == 'err_spamguard_noflood':
            raise ValueError("Fedora Pastebin server ERROR: Poster's IP rejected as trying to flood")
        elif err == 'err_spamguard_stealth':
            raise ValueError("Fedora Pastebin server ERROR: Paste input triggered spam filter")
        elif err == 'err_spamguard_ipban':
            raise ValueError("Fedora Pastebin server ERROR: Poster's IP rejected as permanently banned")
        elif err == 'err_author_numeric':
            raise ValueError("Fedora Pastebin server ERROR: Poster's author should be alphanumeric")
        else:
            raise ValueError("Fedora Pastebin server ERROR: '{0}'".format(err))
    # Put together URL with optional hash if requested
    pasteUrl = '{0}/{1}'.format(url, j['result']['id'])
    if 'yes' in private and j['result'].has_key('hash'):
        pasteUrl += '/{0}'.format(j['result']['hash'])
    return pasteUrl


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
        "  See <http://github.com/ryran/rhsecapi> to report bugs or RFEs").format(version)
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
        '--q-before', metavar="YYYY-MM-DD",
        help="Narrow down results to before a certain time period")
    g_listByAttr.add_argument(
        '--q-after', metavar="YYYY-MM-DD",
        help="Narrow down results to after a certain time period")
    g_listByAttr.add_argument(
        '--q-bug', metavar="BZID",
        help="Narrow down results by Bugzilla ID (specify one or more, e.g.: '1326598,1084875')")
    g_listByAttr.add_argument(
        '--q-advisory', metavar="RHSA",
        help="Narrow down results by errata advisory (specify one or more, e.g.: 'RHSA-2016:0614,RHSA-2016:0610')")
    g_listByAttr.add_argument(
        '--q-severity', metavar="IMPACT", choices=['low', 'moderate', 'important', 'critical'],
        help="Narrow down results by severity rating (specify one of 'low', 'moderate', 'important', or 'critical')")
    g_listByAttr.add_argument(
        '--q-product', metavar="PRODUCT",
        help="Narrow down results by product name via case-insensitive regex (e.g.: 'linux 7' or 'openstack platform [89]'); the API checks this against the 'FIXED_RELEASES' field so will only match CVEs where PRODUCT matches the 'product_name' of some released errata")
    g_listByAttr.add_argument(
        '--q-package', metavar="PKG",
        help="Narrow down results by package name (e.g.: 'samba' or 'thunderbird')")
    g_listByAttr.add_argument(
        '--q-cwe', metavar="CWEID",
        help="Narrow down results by CWE ID (specify one or more, e.g.: '295,300')")
    g_listByAttr.add_argument(
        '--q-cvss', metavar="SCORE",
        help="Narrow down results by CVSS base score (e.g.: '8.0')")
    g_listByAttr.add_argument(
        '--q-cvss3', metavar="SCORE",
        help="Narrow down results by CVSSv3 base score (e.g.: '5.1')")
    g_listByAttr.add_argument(
        '--q-empty', action='store_true',
        help="Allow performing an empty search; when used with no other --q-xxx options, this will return the first 1000 of the most recent CVEs (subject to below PAGESZ & PAGENUM)")
    g_listByAttr.add_argument(
        '--q-pagesize', metavar="PAGESZ", type=int,
        help="Set a cap on the number of results that will be returned (default: 1000)")
    g_listByAttr.add_argument(
        '--q-pagenum', metavar="PAGENUM", type=int,
        help="Select what page number to return (default: 1); only relevant when there are more than PAGESZ results")
    g_listByAttr.add_argument(
        '--q-raw', metavar="RAWQUERY", action='append',
        help="Narrow down results by RAWQUERY (e.g.: '--q-raw a=x --q-raw b=y'); this allows passing arbitrary params (e.g. something new that is unknown to {0})".format(prog))
    # New group
    g_listByIava = p.add_argument_group(
        'RETRIEVE SPECIFIC IAVAS')
    g_listByIava.add_argument(
        '-i', '--iava', dest='iavas', metavar='YYYY-?-NNNN', action='append', 
        help="Retrieve notice details for an IAVA number; specify option multiple times to retrieve multiple IAVAs at once (use below --extract-cves option to lookup mapped CVEs)")
    # New group
    g_getCve = p.add_argument_group(
        'RETRIEVE SPECIFIC CVES')
    g_getCve.add_argument(
        'cves', metavar="CVE-YYYY-NNNN", nargs='*',
        help="Retrieve a CVE or list of CVEs (e.g.: 'CVE-2016-5387'); note that case-insensitive regex-matching is done -- extra characters & duplicate CVEs will be discarded")
    g_getCve.add_argument(
        '-x', '--extract-cves', action='store_true',
        help="Extract CVEs from search query (as initiated by at least one of the --q-xxx options or the --iava option)")
    g_getCve.add_argument(
        '-0', '--stdin', action='store_true',
        help="Extract CVEs from stdin (CVEs will be matched by case-insensitive regex '{0}' and duplicates will be discarded); note that terminal width auto-detection is not possible in this mode and WIDTH defaults to '70' (but can be overridden with '--width')".format(rhsda.cve_regex_string))
    # New group
    g_cveDisplay = p.add_argument_group(
        'CVE DISPLAY OPTIONS')
    g_cveDisplay0 = g_cveDisplay.add_mutually_exclusive_group()
    g_cveDisplay0.add_argument(
        '-f', '--fields', metavar="FIELDS", default='BASE',
        help="Customize field display via comma-separated case-insensitive list (default: {0}); see --all-fields option for full list of official API-provided fields; shorter field aliases: {1}; optionally prepend FIELDS with plus (+) sign to add fields to the default (e.g., '-f +iava,cvss3') or a caret (^) to remove fields from all-fields (e.g., '-f ^mitigation,severity')".format(", ".join(rhsda.cveFields.base), ", ".join(rhsda.cveFields.aliases_printable)))
    g_cveDisplay0.add_argument(
        '-a', '--all-fields', dest='fields', action='store_const',
        const='ALL',
        help="Display all supported fields (currently: {0})".format(", ".join(rhsda.cveFields.all)))
    g_cveDisplay0.add_argument(
        '-m', '--most-fields', dest='fields', action='store_const',
        const='MOST',
        help="Display all fields mentioned above except the heavy-text ones -- (excludes: {0})".format(", ".join(rhsda.cveFields.not_most)))
    g_cveDisplay.add_argument(
        '-p', '--product',
        help="Spotlight a particular PRODUCT via case-insensitive regex; this hides CVEs where 'FIXED_RELEASES' or 'FIX_STATES' don't have an item with 'cpe' (e.g. 'cpe:/o:redhat:enterprise_linux:7') or 'product_name' (e.g. 'Red Hat Enterprise Linux 7') matching PRODUCT; this also hides all items in 'FIXED_RELEASES' & 'FIX_STATES' that don't match PRODUCT")
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
        '-w', '--wrap', metavar="WIDTH", dest='wrapWidth', nargs='?', default=1, const=70, type=int,
        help="Change wrap-width of long fields (acknowledgement, details, statement, mitigation, references) in non-json output (default: wrapping WIDTH equivalent to TERMWIDTH-2 unless using '--pastebin' where default WIDTH is '168'; specify '0' to disable wrapping; WIDTH defaults to '70' if option is used but WIDTH is omitted)")
    g_general.add_argument(
        '-c', '--count', action='store_true',
        help="Exit after printing CVE counts")
    g_general.add_argument(
        '-l', '--loglevel', choices=['debug','info','notice','warning'], default='notice',
        help="Configure logging level threshold; lower from the default of 'notice' to see extra details printed to stderr")
    g_general.add_argument(
        '-t', '--threads', metavar="THREDS", type=int, default=rhsda.numThreadsDefault,
        help="Set number of concurrent worker threads to allow when making CVE queries (default on this system: {0})".format(rhsda.numThreadsDefault))
    g_general.add_argument(
        '-P', '--pastebin', action='store_true',
        help="Send output to Fedora Project Pastebin (paste.fedoraproject.org) and print only URL to stdout")
    g_general.add_argument(
        '-E', '--pexpire', metavar="DAYS", nargs='?', const=1, default=28, type=int,
        help="Set time in days after which paste will be deleted (defaults to '28'; specify '0' to disable expiration; DAYS defaults to '1' if option is used but DAYS is omitted)")
    g_general.add_argument(
        '--dryrun', action='store_true',
        help="Skip CVE retrieval; this option only makes sense in concert with --stdin, for the purpose of quickly getting a printable list of CVE ids from stdin")
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
        sys.exit()
    # Add search params to dict
    o.searchParams = {
        'before': o.q_before,
        'after': o.q_after,
        'bug': o.q_bug,
        'advisory': o.q_advisory,
        'severity': o.q_severity,
        'product': o.q_product,
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
    # Check for search params (--q-xxx) to determine if performing search
    if all(val is None for val in o.searchParams.values()) and not o.q_empty:
        o.doSearch = False
    else:
        o.doSearch = True
        if o.iavas:
            print("{0}: error: --q-xxx options not allowed in concert with -i/--iava".format(prog), file=sys.stderr)
            sys.exit(1)
        if o.cves or o.stdin:
            print("{0}: error: --q-xxx options not allowed in concert with CVE args".format(prog), file=sys.stderr)
            sys.exit(1)
    if o.cves:
        o.cves = rhsda.extract_cves_from_input(o.cves, "cmdline")
        if not o.cves:
            o.showUsage = True
    if o.stdin and not sys.stdin.isatty():
        found = rhsda.extract_cves_from_input(sys.stdin)
        o.cves.extend(found)
    # If no search (--q-xxx) and no CVEs mentioned
    if not o.showUsage and not (o.doSearch or o.cves or o.iavas):
        logger.error("Must specify CVEs/IAVAs to retrieve or a search to perform (--q-xxx opts)")
        o.showUsage = True
    if o.showUsage:
        p.print_usage()
        print("\nRun {0} --help for full help page\n\n{1}".format(prog, epilog))
        sys.exit()
    # If autowrap and using pastebin, set good width
    if o.wrapWidth == 1 and o.pastebin:
        o.wrapWidth = 168
    if o.json:
        o.outFormat = 'jsonpretty'
    else:
        o.outFormat = 'plaintext'
    logger.setLevel(o.loglevel.upper())
    return o


def main(opts):
    apiclient = rhsda.ApiClient(opts.loglevel)
    from os import environ
    if environ.has_key('RHSDA_URL') and environ['RHSDA_URL'].startswith('http'):
        apiclient.cfg.apiUrl = environ['RHSDA_URL']
    searchOutput = ""
    iavaOutput = ""
    cveOutput = ""
    if opts.doSearch:
        if opts.extract_cves:
            result = apiclient.cve_search_query(params=opts.searchParams, outFormat='list')
            for cve in result:
                opts.cves.append(cve)
        elif opts.count:
            result = apiclient.cve_search_query(params=opts.searchParams)
        else:
            searchOutput = apiclient.cve_search_query(params=opts.searchParams, outFormat=opts.outFormat, urls=opts.printUrls)
            if not opts.json:
                searchOutput += "\n"
            if not opts.pastebin:
                print(file=sys.stderr)
                print(searchOutput, end="")
    if opts.iavas:
        logger.debug("IAVAs: {0}".format(opts.iavas))
        if opts.extract_cves:
            result = apiclient.mget_iavas(iavas=opts.iavas, numThreads=opts.threads, onlyCount=opts.count, outFormat='list')
            opts.cves.extend(result)
        elif opts.count:
            result = apiclient.mget_iavas(iavas=opts.iavas, numThreads=opts.threads, onlyCount=opts.count)
        else:
            iavaOutput = apiclient.mget_iavas(iavas=opts.iavas, numThreads=opts.threads, outFormat=opts.outFormat, urls=opts.printUrls)
            if not opts.pastebin:
                print(file=sys.stderr)
                print(iavaOutput, end="")
    if opts.cves:
        originalCount = len(opts.cves)
        # Converting to a set removes duplicates
        opts.cves = list(set(opts.cves))
        dupesRemoved = originalCount - len(opts.cves)
        if dupesRemoved:
            logger.log(25, "{0} duplicate CVEs removed".format(dupesRemoved))
        if opts.dryrun:
            logger.log(25, "Skipping CVE retrieval due to --dryrun; would have retrieved: {0}".format(len(opts.cves)))
            cveOutput = " ".join(opts.cves) + "\n"
        else:
            if iavaOutput:
                print(file=sys.stderr)
            cveOutput = apiclient.mget_cves(cves=opts.cves, numThreads=opts.threads, onlyCount=opts.count, outFormat=opts.outFormat, urls=opts.printUrls, fields=opts.fields, wrapWidth=opts.wrapWidth, product=opts.product)
    if opts.count:
        return
    if opts.pastebin:
        opts.p_lang = 'text'
        if opts.json:
            opts.p_lang = 'Python'
        data = searchOutput + iavaOutput + cveOutput
        try:
            response = fpaste_it(inputdata=data, author=prog, lang=opts.p_lang, expire=opts.pexpire)
        except ValueError as e:
            print(e, file=sys.stderr)
            logger.error("Submitting to pastebin failed; print results to stdout instead? [y]")
            answer = raw_input("> ")
            if "y" in answer or len(answer) == 0:
                print(data, end="")
        else:
            print(response)
    elif opts.cves:
        print(file=sys.stderr)
        print(cveOutput, end="")


if __name__ == "__main__":
    try:
        opts = parse_args()
        main(opts)
    except KeyboardInterrupt:
        logger.error("Received KeyboardInterrupt; exiting")
        sys.exit()
