#!/usr/bin/python

from sys import stdin, stdout, exit
from sys import path as syspath
from os.path import dirname, abspath
from os.path import join as pathjoin
curdir = dirname(abspath(__file__))
topdir = abspath(pathjoin(curdir, '..'))
syspath.append(curdir)
syspath.append(topdir)
from rhsda import ApiClient
from re import match as rematch
from pprint import pprint
from datetime import datetime
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pickle import dumps as pickle_dump
from pickle import loads as pickle_load
from json import dumps as json_dump
from json import loads as json_load
import logging
from logging import debug, info, warning, critical
from rpmUtils.miscutils import splitFilename, compareEVR

exitvals = {
    'OK': 0,
    'WARNING': 1,
    'CRITICAL': 2,
    'UNKNOWN': 3,
}

tmppath = '/var/tmp'

#logging.basicConfig(format = '%(message)s', level=logging.DEBUG)
logging.basicConfig(format = '%(message)s', level=logging.WARNING)

engine = create_engine('sqlite:///%s/updates_cache.db' % tmppath)
Base = declarative_base()
Session = sessionmaker(bind=engine)

class CVE_cache(Base):
    """
    Define our CVE cache table
    name = RPM package name
    date = the date we queried CVEs for
    product = the product name we used to query the API
    data = The serialized data we got from the API
    """

    __tablename__ = 'cvecache'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    date = Column(String) # TODO: Well, not good, but for the moment...
    product = Column(String)
    data = Column(String)


    def __repr__(self):
        return "<CVE_cache(name='%s', date>='%s', product='%s')>" % (
                self.name,
                self.date,
                self.product,
        )


def main(input = stdin, quiet = False):
    try:
        installed_packages = dict()
        os_maj_version = None
        os_min_version = None
        os_name = None
        api = ApiClient(logLevel='error')

        session = Session()

        severity = 'low'
        output_text = ''
        issues = 0

        try:
            Base.metadata.create_all(engine)
        except Exception as e:
            debug('Exception: %s' % e)
            pass

        # Iterate of the lines from stdin
        for line in input:
            # Ignore lines that are commented out or empty lines
            if line.startswith('#'): continue
            if rematch(r"""^\s+$""", line): continue
            
            (buildtime, name, version, release) = line.rstrip().split(' ')

            # Ignore public gpg keys
            if name == 'gpg-pubkey': continue

            # Check if it's the OS release package (redhat-release, centos-release,
            # fedora-release [note: not supported!]
            re_result = rematch(r"""^(fedora|redhat|centos)-release.*""", name)
            if re_result:
                os_name = re_result.group(1)
                if os_name == 'fedora':
                    print('Fedora is not supported yet')
                    exit(0)
                re_result = rematch(r"""^(\d+).*""", version)
                os_maj_version = re_result.group(1)

            # Figure out which package is the latest and skip packages with the same
            # NVR, but different arch
            if name in installed_packages:
                if version == installed_packages[name]['version'] and \
                   release == installed_packages[name]['release']:
                    # Skip. It's most probably the same package, but different
                    # arch. Eg. i686/x86_64 on x64 systems
                    continue
                if buildtime < installed_packages[name]['buildtime']:
                    debug('%s-%s-%s (%s) is older than %s-%s-%s (%s)' % (
                        name, version, release, buildtime,
                        name,
                        installed_packages[name]['version'],
                        installed_packages[name]['release'],
                        installed_packages[name]['buildtime'])
                    )
                    continue
            installed_packages[name] = {
                'buildtime': buildtime,
                'version': version,
                'release': release,
            }

        info('This is a: %s %s' % (os_name, os_maj_version))
        for name in installed_packages:
            search_date = datetime.fromtimestamp(
                    float(installed_packages[name]['buildtime'])
            ).strftime("%Y-%m-%d")

            # Querying with minor release doesn't work (ATM?)
            if os_min_version and 1 == 0:
                product = "(linux %s.%s)" % (os_maj_version, os_min_version)
            else:
                product = "(linux %s)" % os_maj_version
            debug('Query product: %s' % product)

            # Check if we already have any information in the database
            query = session.query(CVE_cache).filter_by(
                name = name,
                product = product,
                date = search_date)

            data = None
            # Nothing in DB, query online
            if not query.count() > 0:
                data = api.find_cves(after = search_date,
                                     package = name,
                                     product = product)

                new_data = []
                for item in data:
                    debug('Item: %s' % item)
                    packages = []
                    for pkg in item['affected_packages']:
                        # TODO? We do not care about epoch ATM
                        (pkg_name, pkg_version, pkg_release) = splitFilename(pkg)[0:3]

                        if pkg_name == name:
                            print('pkg: %s' % pkg_name)
                            if compareEVR([0, pkg_version, pkg_release],
                                    [0, installed_packages[name]['version'],
                                        installed_packages[name]['release']]) > 0:
                                packages.append(pkg)
                        
                    # If some package names match, add it.
                    if packages:
                        item['affected_packages'] = packages
                        new_data.append(item)
                data = new_data


                # Debug output (found something or not...)
                if data:
                    debug('Issues for %s: %s' % (name, data))
                else:
                    debug('Nothing found for %s' % name)

                # Whatever the result was, we cache it
                dbobj = CVE_cache(name = name, product = product, date = search_date, data = pickle_dump(data))
                session.add(dbobj)
                session.commit()

            # Found data in DB, unpickle
            else:
                data = pickle_load(query.one().data)
                if data:
                    debug('(Cached) issues for %s: %s' % (name, data))
                else:
                    debug('(Cached) Nothing found for %s' % name)

            # We have data, either fresh from the API (web) or from the
            # database
            if data:
                output_text += '%s has security issues:\n' % name
                for issue in data:
                    output_text += '  * %s (%s)\n    - %s\n' % (
                        issue['bugzilla_description'].rstrip().lstrip(), issue['severity'], issue['resource_url'])
                    if issue['severity'] == 'moderate' and severity != 'important':
                        severity = 'moderate'
                    elif issue['severity'] == 'important' and severity != 'important':
                        severity = 'important'

                issues += 1

        session.close()
        level = 'OK'
        if output_text:
            if severity == 'important' or severity == 'moderate':
                level = 'CRITICAL'
            elif severity == 'low':
                level = 'WARNING'
            if not quiet:
                print('%s: %i security issues found in %i packages (highest severity: %s)' % (level, issues, len(installed_packages), severity))
                print(output_text)
            exit(exitvals[level])

    except KeyboardInterrupt as e:
        stdout.flush()
        if not quiet:
            print('UNKNOWN: %s' % e)
        exit(exitvals['UNKNOWN'])
    except Exception as e:
        stdout.flush()
        if not quiet:
            print('UNKNOWN: %s' % e)
        exit(exitvals['UNKNOWN'])

    if not quiet:
        print('OK: Obviously, no issues were found')
    exit(exitvals['OK'])

if __name__ == '__main__':
    """
    Simple example script for rhsda, showing how to find CVEs that apply to
    your packages. Generate the list with:
      rpm -qa --qf '%{buildtime} %{name} %{version} %{release}\n'
    """
    main()
