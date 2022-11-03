#
# spec file for package obs-signd
#
# Copyright (c) 2022 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


Name:           obs-signd
Summary:        The sign daemon
License:        GPL-2.0-only
Group:          Productivity/Networking/Web/Utilities

Version:        2.6.1
Release:        0

URL:            http://en.opensuse.org/Build_Service
Source:         obs-sign-%version.tar.xz
Source1:        obs-signd-rpmlintrc
Requires:       user(obsrun)
%if 0%{?suse_version}
PreReq:         %fillup_prereq
PreReq:         permissions
%endif

%if ! %{defined _fillupdir}
  %define _fillupdir /var/adm/fillup-templates
%endif

# the following build requires are needed for the testsuite
%if 0%{?suse_version}
BuildRequires:  gpg2
%else
BuildRequires:  gpg
%endif
BuildRequires:  make
BuildRequires:  openssl

%description
The openSUSE Build Service sign client and daemon.

This daemon can be used to sign anything via gpg, but it speaks with a remote server
to avoid the need to host the private key on the same server.

%prep
%setup -n obs-sign-%version

%build
make CFLAGS="$RPM_OPT_FLAGS -fpie -D_FILE_OFFSET_BITS=64" LDFLAGS="-pie"

%check
make test

%install
# run level script
mkdir -p %{buildroot}%{_unitdir}
install -m 0755 dist/signd.service %{buildroot}%{_unitdir}/obssignd.service
install -d -m 0755 %{buildroot}%{_sbindir}
ln -sf /usr/sbin/service %{buildroot}%{_sbindir}/rcobssignd

# man pages
install -d -m 0755 %{buildroot}%{_mandir}/man{5,8}
install -d -m 0755 %{buildroot}/usr/bin
for j in `ls sig*.{5,8}`; do
  gzip -9 ${j}
done
for k in 5 8; do
  install -m 0644 sig*.${k}.gz %{buildroot}%{_mandir}/man${k}/
done

# binaries and configuration
install -d -m 0755 %{buildroot}/etc/permissions.d
install -m 0755 signd %{buildroot}/usr/sbin/
install -m 0750 sign %{buildroot}/usr/bin/
install -m 0644 sign.conf %{buildroot}/etc/
install -m 0644 dist/sign.permission %{buildroot}/etc/permissions.d/sign

# install fillups
FILLUP_DIR=%{buildroot}%{_fillupdir}
install -d -m 755 $FILLUP_DIR
install -m 0644 dist/sysconfig.signd $FILLUP_DIR/

%pre
%service_add_pre obssignd.service

%preun
%service_del_preun obssignd.service

%post
%service_add_post obssignd.service
%if 0%{?suse_version} > 1220
%set_permissions /etc/permissions.d/sign
%else
%run_permissions
%endif
%fillup_only -n signd

%postun
%service_del_postun obssignd.service

%files
%config(noreplace) /etc/sign.conf
%verify(not mode) %attr(4750,root,obsrun) /usr/bin/sign
%attr(0755,root,root) /usr/sbin/signd
%attr(0755,root,root) /usr/sbin/rcobssignd
%attr(0644,root,root) %{_unitdir}/obssignd.service
%{_fillupdir}/sysconfig.signd
/etc/permissions.d/sign
%doc %{_mandir}/man*/*

%changelog
