%{!?python_sitelib: %define python_sitelib %(python -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
 
Summary: Configuration file merge/update tool
Name: dispatch-conf
Version: 0.2
Release: 11%{?dist}
License: GPLv2
Group: System Environment/Base
Source0: http://github.com/bks/dispatch-conf-rpm/tarball/v%{version}

BuildArch: noarch
BuildRequires: python
Requires: python >= 2.6
Requires: diffutils
Requires: less
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
dispatch-conf is a tool which scans the system configuration file directories
for updated configuration files (i.e. *.rpmnew) and helps the user view and
merge the updates into their current configuration. It is also capable of
maintaining an RCS repository of all files which it has updated.

%prep
%setup -q
%build
make

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install
install -m 644 dispatch-conf.conf $RPM_BUILD_ROOT/%{_sysconfdir}/dispatch-conf.conf

%clean
rm -rf $RPM_BUILD_ROOT

%defattr(-, root, root, -)
%config(noreplace) %{_sysconfdir}/dispatch-conf.conf
%{_bindir}/dispatch-conf
%{python_sitelib}/dispatch_conf

%changelog
* Sun Mar 1 2009 Benjamin K. Stuhl <benjamin.stuhl@colorado.edu> 0.2
- initial version
