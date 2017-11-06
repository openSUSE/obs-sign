#
# spec file for package obs-signd
#
# Copyright (c) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           obs-signd
Summary:        The sign daemon
License:        GPL-2.0
Group:          Productivity/Networking/Web/Utilities

Version:        2.4.2
Release:        0

Url:            http://en.opensuse.org/Build_Service
Source:         obs-sign-%version.tar.xz
Source1:        obs-signd-rpmlintrc
Requires:       gpg2_signd_support
%if 0%{?suse_version:1}
PreReq:         %fillup_prereq %insserv_prereq permissions
%endif
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
The openSUSE Build Service sign client and daemon.

This daemon can be used to sign anything via gpg, but it speaks with a remote server
to avoid the need to host the private key on the same server.

%prep
%setup -n obs-sign-%version

%build
#
# make sign binary
#
gcc $RPM_OPT_FLAGS -fPIC -pie -o sign sign.c

%install
# run level script
mkdir -p $RPM_BUILD_ROOT/etc/init.d/ $RPM_BUILD_ROOT/usr/sbin
install -m 0755 dist/obssignd $RPM_BUILD_ROOT/etc/init.d/
ln -sf /etc/init.d/obssignd $RPM_BUILD_ROOT/usr/sbin/rcobssignd

# man pages
install -d -m 0755 $RPM_BUILD_ROOT%{_mandir}/man{5,8}
install -d -m 0755 $RPM_BUILD_ROOT/usr/bin
for j in `ls sig*.{5,8}`; do
  gzip -9 ${j}
done
for k in 5 8; do
  install -m 0644 sig*.${k}.gz $RPM_BUILD_ROOT%{_mandir}/man${k}/
done

# binaries and configuration
install -d -m 0755 $RPM_BUILD_ROOT/etc/permissions.d
install -m 0755 signd $RPM_BUILD_ROOT/usr/sbin/
install -m 0750 sign $RPM_BUILD_ROOT/usr/bin/
install -m 0644 sign.conf $RPM_BUILD_ROOT/etc/
install -m 0644 dist/sign.permission $RPM_BUILD_ROOT/etc/permissions.d/sign

# install fillups
FILLUP_DIR=$RPM_BUILD_ROOT/var/adm/fillup-templates
install -d -m 755 $FILLUP_DIR
install -m 0644 dist/sysconfig.signd $FILLUP_DIR/

%pre
/usr/sbin/groupadd -r obsrun 2> /dev/null || :
/usr/sbin/useradd -r -o -s /bin/false -c "User for build service backend" -d /usr/lib/obs -g obsrun obsrun 2> /dev/null || :

%preun
%stop_on_removal obssignd

%post
%if 0%{?suse_version} > 1220
%set_permissions /etc/permissions.d/sign
%else
%run_permissions
%endif
%fillup_and_insserv

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config(noreplace) /etc/sign.conf
%verify(not mode) %attr(4750,root,obsrun) /usr/bin/sign
%attr(0755,root,root) /usr/sbin/signd
%attr(0755,root,root) /usr/sbin/rcobssignd
%attr(0755,root,root) /etc/init.d/obssignd
/var/adm/fillup-templates/sysconfig.signd
/etc/permissions.d/sign
%doc %{_mandir}/man*/*

%changelog
