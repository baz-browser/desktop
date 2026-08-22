%define _tarball %{?_tarball}%{!?_tarball:baz.linux-x86_64.tar.xz}

Name:           baz-browser
Version:        VERSION_PLACEHOLDER
Release:        1%{?dist}
Summary:        Baz Browser, a Firefox-based web browser
License:        MPL-2.0
URL:            https://example.com/baz
Group:          Applications/Internet
Requires:       gtk3, alsa-lib, dbus-libs, dbus-glib, libdrm, libX11-xcb, libXt, libcurl
AutoReqProv:    no
BuildArch:      x86_64

Source0:        %{_tarball}
Source1:        baz.desktop

%description
Baz is a Firefox-based web browser with hardened networking (brxon)
built in.

%prep


%build


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/opt/baz
tar -xJf %{SOURCE0} -C %{buildroot}/opt/baz --strip-components=1

mkdir -p %{buildroot}/usr/bin
ln -sf /opt/baz/baz %{buildroot}/usr/bin/baz

mkdir -p %{buildroot}/usr/share/applications
install -m 0644 %{SOURCE1} %{buildroot}/usr/share/applications/baz.desktop

mkdir -p %{buildroot}/usr/share/icons
cp -r %{_sourcedir}/icons/hicolor %{buildroot}/usr/share/icons/hicolor

%files
%defattr(-,root,root,-)
/opt/baz
/usr/bin/baz
/usr/share/applications/baz.desktop
/usr/share/icons/hicolor

%clean
rm -rf %{buildroot}
