%{!?__python2: %global __python2 %__python}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python2_sitearch: %global python2_sitearch %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

# Disable the debuginfo build operation
%global debug_package %{nil}

%if 0%{?fedora}
%bcond_without python3
%else
%bcond_with python3
%endif

Name:       {{{ git_name }}}
Version:    {{{ git_version }}}
Release:    1%{?dist}
Summary:    Provides a simple interface for the Red Hat Security Data API

License:    GPL
URL:        https://github.com/RedHatOfficial/rhsecapi
Source:     {{{ git_pack }}}

BuildRequires:  python2-devel python2-setuptools
%if %{with python3}
BuildRequires:  python3-devel python3-setuptools
%endif # with python3


%description
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

%if %{with python3}
%package     -n python3-%{name}
Summary:    Provides a simple interface for the Red Hat Security Data API

%description -n python3-%{name}
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

%endif # with python3


%prep
%autosetup -c
mv %{name}-%{version} python2

%if %{with python3}
cp -a python2 python3
%endif # with python3


%build
pushd python2
# Remove CFLAGS=... for noarch packages (unneeded)
CFLAGS="$RPM_OPT_FLAGS" %{__python2} setup.py build
popd

%if %{with python3}
pushd python3
# Remove CFLAGS=... for noarch packages (unneeded)
CFLAGS="$RPM_OPT_FLAGS" %{__python3} setup.py build
popd
%endif # with python3


%install
rm -rf $RPM_BUILD_ROOT

# Must do the python3 install first because the scripts in /usr/bin are
# overwritten with every setup.py install (and we want the python2 version
# to be the default for now).
%if %{with python3}
pushd python3
%{__python3} setup.py install -O1 --root $RPM_BUILD_ROOT/
popd
%endif # with python3

pushd python2
%{__python2} setup.py install -O1 --root $RPM_BUILD_ROOT/
popd


%files
%{_bindir}/*
# For noarch packages: sitelib
%{python2_sitelib}/*

%if %{with python3}
%files -n python3-%{name}
%{_bindir}/*
# For noarch packages: sitelib
%{python3_sitelib}/*
%endif # with python3


%changelog
{{{ git_changelog }}}

