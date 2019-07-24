import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

LONG_DESCRIPTION = """
Leverage Red Hat's Security Data API to find CVEs by various attributes
(date, severity, scores, package, IAVA, etc). Retrieve customizable details
about found CVEs or about specific CVE ids input on cmdline. Parse
arbitrary stdin for CVE ids and generate a customized report, optionally
sending it straight to pastebin. Searches are done via a single
instantaneous http request and CVE retrieval is parallelized, utilizing
multiple threads at once. Python requests is used for all remote
communication, so proxy support is baked right in. BASH intelligent
tab-completion is supported via optional Python argcomplete module. Python2
tested on RHEL6, RHEL7, & Fedora and Python3 on Fedora but since it doesnt
integrate with RHN/RHSM/yum/Satellite, it can be used on any
internet-connected machine. Feedback, feature requests, and code
contributions welcome.
"""
setup(
    name = 'rhsecapi',
    version = '1.0.2',
    author = 'Ryan Sawhill Aroha',
    author_email = 'rsaw@redhat.com',
    description = 'Provides a simple interface for the Red Hat Security Data API',
    license = 'GPL',
    packages = find_packages(),

    scripts = ['bin/rhsecapi'],
    install_requires = [
        'requests',
    ],

    long_description=LONG_DESCRIPTION
)


