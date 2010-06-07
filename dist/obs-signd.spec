#
# spec file for package obs-server
#
# Copyright (c) 2008 SUSE LINUX Products GmbH, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://bugs.opensuse.org/
#



Name:           obs-signd
Summary:        The sign daemon

Version:        1.9.92

Release:        0
License:        GPL
Group:          Productivity/Networking/Web/Utilities
Url:            http://en.opensuse.org/Build_Service
Source:         sign-%version.tar.bz2
Source1:        sign-rpmlintrc
Requires:       gpg2_signd_support
%if 0%{?suse_version:1}
PreReq:         %fillup_prereq %insserv_prereq permissions
%endif
Autoreqprov:    on
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
The openSUSE Build Service sign client and daemon.

This daemon can be used to sign anything via gpg, but it speaks with a remote server
to avoid the need to host the private key on the same server.

Authors:
--------
    The openSUSE Team <opensuse-buildservice@opensuse.org>

%prep
%setup -q -n sign-%version

%build
#
# make sign binary
#
gcc $RPM_OPT_FLAGS -o sign sign.c

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

%preun
%stop_on_removal obssignd

%post
%run_permissions
%fillup_and_insserv

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config(noreplace) /etc/sign.conf
%attr(4750,root,root) /usr/bin/sign
%attr(0755,root,root) /usr/sbin/signd
%attr(0755,root,root) /usr/sbin/rcobssignd
%attr(0755,root,root) /etc/init.d/obssignd
/var/adm/fillup-templates/sysconfig.signd
/etc/permissions.d/sign
%doc %{_mandir}/man*/*

