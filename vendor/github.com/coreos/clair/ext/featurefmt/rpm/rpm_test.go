// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coreos/clair/database"
	"github.com/coreos/clair/ext/featurefmt"
	"github.com/coreos/clair/ext/versionfmt/rpm"
)

var expectedBigCaseInfo = []database.Feature{
	{"libmount", "2.32.1-1.fc28", "rpm", "binary"},
	{"libffi", "3.1-16.fc28", "rpm", "binary"},
	{"libunistring", "0.9.10-1.fc28", "rpm", "binary"},
	{"fedora-repos", "28-5", "rpm", "binary"},
	{"libarchive", "3.3.1-4.fc28", "rpm", "source"},
	{"langpacks", "1.0-12.fc28", "rpm", "source"},
	{"readline", "7.0-11.fc28", "rpm", "source"},
	{"gzip", "1.9-3.fc28", "rpm", "source"},
	{"libverto", "0.3.0-5.fc28", "rpm", "source"},
	{"ncurses-base", "6.1-5.20180224.fc28", "rpm", "binary"},
	{"libfdisk", "2.32.1-1.fc28", "rpm", "binary"},
	{"libselinux", "2.8-1.fc28", "rpm", "source"},
	{"nss-util", "3.38.0-1.0.fc28", "rpm", "source"},
	{"mpfr", "3.1.6-1.fc28", "rpm", "source"},
	{"libunistring", "0.9.10-1.fc28", "rpm", "source"},
	{"libpcap", "14:1.9.0-1.fc28", "rpm", "binary"},
	{"libarchive", "3.3.1-4.fc28", "rpm", "binary"},
	{"gmp", "1:6.1.2-7.fc28", "rpm", "binary"},
	{"crypto-policies", "20180425-5.git6ad4018.fc28", "rpm", "source"},
	{"gzip", "1.9-3.fc28", "rpm", "binary"},
	{"fedora-release", "28-2", "rpm", "source"},
	{"zlib", "1.2.11-8.fc28", "rpm", "binary"},
	{"crypto-policies", "20180425-5.git6ad4018.fc28", "rpm", "binary"},
	{"lz4", "1.8.1.2-4.fc28", "rpm", "source"},
	{"keyutils", "1.5.10-6.fc28", "rpm", "source"},
	{"gpgme", "1.10.0-4.fc28", "rpm", "binary"},
	{"libgpg-error", "1.31-1.fc28", "rpm", "binary"},
	{"gnutls", "3.6.3-4.fc28", "rpm", "source"},
	{"coreutils", "8.29-7.fc28", "rpm", "source"},
	{"libsepol", "2.8-1.fc28", "rpm", "source"},
	{"libssh", "0.8.2-1.fc28", "rpm", "binary"},
	{"libpwquality", "1.4.0-7.fc28", "rpm", "binary"},
	{"dnf-conf", "2.7.5-12.fc28", "rpm", "binary"},
	{"basesystem", "11-5.fc28", "rpm", "source"},
	{"setup", "2.11.4-1.fc28", "rpm", "binary"},
	{"libmetalink", "0.1.3-6.fc28", "rpm", "source"},
	{"texinfo", "6.5-4.fc28", "rpm", "source"},
	{"expat", "2.2.5-3.fc28", "rpm", "source"},
	{"ncurses", "6.1-5.20180224.fc28", "rpm", "source"},
	{"libpwquality", "1.4.0-7.fc28", "rpm", "source"},
	{"pcre", "8.42-3.fc28", "rpm", "binary"},
	{"sssd", "1.16.3-2.fc28", "rpm", "source"},
	{"basesystem", "11-5.fc28", "rpm", "binary"},
	{"systemd-pam", "238-9.git0e0aa59.fc28", "rpm", "binary"},
	{"python3-six", "1.11.0-3.fc28", "rpm", "binary"},
	{"libcurl", "7.59.0-6.fc28", "rpm", "binary"},
	{"qrencode", "3.4.4-5.fc28", "rpm", "source"},
	{"xz", "5.2.4-2.fc28", "rpm", "source"},
	{"libpkgconf", "1.4.2-1.fc28", "rpm", "binary"},
	{"libzstd", "1.3.5-1.fc28", "rpm", "binary"},
	{"bash", "4.4.23-1.fc28", "rpm", "binary"},
	{"cyrus-sasl", "2.1.27-0.2rc7.fc28", "rpm", "source"},
	{"ncurses-libs", "6.1-5.20180224.fc28", "rpm", "binary"},
	{"xz-libs", "5.2.4-2.fc28", "rpm", "binary"},
	{"dbus", "1.12.10-1.fc28", "rpm", "source"},
	{"grep", "3.1-5.fc28", "rpm", "binary"},
	{"libusbx", "1.0.22-1.fc28", "rpm", "binary"},
	{"audit", "2.8.4-2.fc28", "rpm", "source"},
	{"sed", "4.5-1.fc28", "rpm", "binary"},
	{"sqlite", "3.22.0-4.fc28", "rpm", "source"},
	{"openldap", "2.4.46-3.fc28", "rpm", "binary"},
	{"gawk", "4.2.1-1.fc28", "rpm", "binary"},
	{"gpgme", "1.10.0-4.fc28", "rpm", "source"},
	{"lvm2", "2.02.177-5.fc28", "rpm", "source"},
	{"nspr", "4.19.0-1.fc28", "rpm", "source"},
	{"libsolv", "0.6.35-1.fc28", "rpm", "source"},
	{"info", "6.5-4.fc28", "rpm", "binary"},
	{"openssl-libs", "1:1.1.0h-3.fc28", "rpm", "binary"},
	{"libxcrypt", "4.1.2-1.fc28", "rpm", "binary"},
	{"libselinux", "2.8-1.fc28", "rpm", "binary"},
	{"libgcc", "8.1.1-5.fc28", "rpm", "binary"},
	{"cracklib", "2.9.6-13.fc28", "rpm", "binary"},
	{"python3-libs", "3.6.6-1.fc28", "rpm", "binary"},
	{"glibc-langpack-en", "2.27-32.fc28", "rpm", "binary"},
	{"json-c", "0.13.1-2.fc28", "rpm", "binary"},
	{"gnupg2", "2.2.8-1.fc28", "rpm", "source"},
	{"openssl", "1:1.1.0h-3.fc28", "rpm", "binary"},
	{"glibc-common", "2.27-32.fc28", "rpm", "binary"},
	{"p11-kit-trust", "0.23.12-1.fc28", "rpm", "binary"},
	{"zstd", "1.3.5-1.fc28", "rpm", "source"},
	{"libxml2", "2.9.8-4.fc28", "rpm", "source"},
	{"dbus", "1:1.12.10-1.fc28", "rpm", "binary"},
	{"ca-certificates", "2018.2.24-1.0.fc28", "rpm", "binary"},
	{"libcomps", "0.1.8-11.fc28", "rpm", "binary"},
	{"nss", "3.38.0-1.0.fc28", "rpm", "binary"},
	{"libcom_err", "1.44.2-0.fc28", "rpm", "binary"},
	{"keyutils-libs", "1.5.10-6.fc28", "rpm", "binary"},
	{"libseccomp", "2.3.3-2.fc28", "rpm", "binary"},
	{"elfutils-libs", "0.173-1.fc28", "rpm", "binary"},
	{"libuuid", "2.32.1-1.fc28", "rpm", "binary"},
	{"pkgconf", "1.4.2-1.fc28", "rpm", "source"},
	{"grep", "3.1-5.fc28", "rpm", "source"},
	{"libpcap", "1.9.0-1.fc28", "rpm", "source"},
	{"deltarpm", "3.6-25.fc28", "rpm", "binary"},
	{"krb5-libs", "1.16.1-13.fc28", "rpm", "binary"},
	{"glibc", "2.27-32.fc28", "rpm", "binary"},
	{"libseccomp", "2.3.3-2.fc28", "rpm", "source"},
	{"libsemanage", "2.8-2.fc28", "rpm", "binary"},
	{"openssl-pkcs11", "0.4.8-1.fc28", "rpm", "binary"},
	{"libxml2", "2.9.8-4.fc28", "rpm", "binary"},
	{"e2fsprogs", "1.44.2-0.fc28", "rpm", "source"},
	{"file-libs", "5.33-7.fc28", "rpm", "binary"},
	{"elfutils-default-yama-scope", "0.173-1.fc28", "rpm", "binary"},
	{"glibc", "2.27-32.fc28", "rpm", "source"},
	{"publicsuffix-list-dafsa", "20180514-1.fc28", "rpm", "binary"},
	{"popt", "1.16-14.fc28", "rpm", "binary"},
	{"libnsl2", "1.2.0-2.20180605git4a062cf.fc28", "rpm", "binary"},
	{"lua-libs", "5.3.4-10.fc28", "rpm", "binary"},
	{"libsemanage", "2.8-2.fc28", "rpm", "source"},
	{"glibc-minimal-langpack", "2.27-32.fc28", "rpm", "binary"},
	{"attr", "2.4.48-3.fc28", "rpm", "source"},
	{"gdbm", "1.14.1-4.fc28", "rpm", "source"},
	{"pkgconf", "1.4.2-1.fc28", "rpm", "binary"},
	{"acl", "2.2.53-1.fc28", "rpm", "source"},
	{"gnutls", "3.6.3-4.fc28", "rpm", "binary"},
	{"fedora-repos", "28-5", "rpm", "source"},
	{"python3-pip", "9.0.3-2.fc28", "rpm", "binary"},
	{"libnsl2", "1.2.0-2.20180605git4a062cf.fc28", "rpm", "source"},
	{"rpm", "4.14.1-9.fc28", "rpm", "binary"},
	{"libutempter", "1.1.6-14.fc28", "rpm", "source"},
	{"libdnf", "0.11.1-3.fc28", "rpm", "source"},
	{"vim-minimal", "2:8.1.328-1.fc28", "rpm", "binary"},
	{"tzdata", "2018e-1.fc28", "rpm", "binary"},
	{"nettle", "3.4-2.fc28", "rpm", "binary"},
	{"python-pip", "9.0.3-2.fc28", "rpm", "source"},
	{"python-six", "1.11.0-3.fc28", "rpm", "source"},
	{"diffutils", "3.6-4.fc28", "rpm", "binary"},
	{"rpm-plugin-selinux", "4.14.1-9.fc28", "rpm", "binary"},
	{"shadow-utils", "2:4.6-1.fc28", "rpm", "binary"},
	{"pkgconf-pkg-config", "1.4.2-1.fc28", "rpm", "binary"},
	{"cracklib-dicts", "2.9.6-13.fc28", "rpm", "binary"},
	{"libblkid", "2.32.1-1.fc28", "rpm", "binary"},
	{"python-setuptools", "39.2.0-6.fc28", "rpm", "source"},
	{"libsss_idmap", "1.16.3-2.fc28", "rpm", "binary"},
	{"libksba", "1.3.5-7.fc28", "rpm", "source"},
	{"sssd-client", "1.16.3-2.fc28", "rpm", "binary"},
	{"curl", "7.59.0-6.fc28", "rpm", "binary"},
	{"pam", "1.3.1-1.fc28", "rpm", "binary"},
	{"libsigsegv", "2.11-5.fc28", "rpm", "binary"},
	{"langpacks-en", "1.0-12.fc28", "rpm", "binary"},
	{"nss-softokn-freebl", "3.38.0-1.0.fc28", "rpm", "binary"},
	{"glib2", "2.56.1-4.fc28", "rpm", "binary"},
	{"python3-gobject-base", "3.28.3-1.fc28", "rpm", "binary"},
	{"libffi", "3.1-16.fc28", "rpm", "source"},
	{"libmodulemd", "1.6.2-2.fc28", "rpm", "source"},
	{"openssl", "1.1.0h-3.fc28", "rpm", "source"},
	{"libyaml", "0.1.7-5.fc28", "rpm", "source"},
	{"pam", "1.3.1-1.fc28", "rpm", "source"},
	{"iptables", "1.6.2-3.fc28", "rpm", "source"},
	{"util-linux", "2.32.1-1.fc28", "rpm", "source"},
	{"libsmartcols", "2.32.1-1.fc28", "rpm", "binary"},
	{"dnf", "2.7.5-12.fc28", "rpm", "binary"},
	{"glib2", "2.56.1-4.fc28", "rpm", "source"},
	{"lua", "5.3.4-10.fc28", "rpm", "source"},
	{"nss-softokn", "3.38.0-1.0.fc28", "rpm", "source"},
	{"python3-dnf", "2.7.5-12.fc28", "rpm", "binary"},
	{"filesystem", "3.8-2.fc28", "rpm", "binary"},
	{"libsss_nss_idmap", "1.16.3-2.fc28", "rpm", "binary"},
	{"pcre2", "10.31-10.fc28", "rpm", "source"},
	{"libyaml", "0.1.7-5.fc28", "rpm", "binary"},
	{"python3-rpm", "4.14.1-9.fc28", "rpm", "binary"},
	{"zlib", "1.2.11-8.fc28", "rpm", "source"},
	{"libutempter", "1.1.6-14.fc28", "rpm", "binary"},
	{"pcre2", "10.31-10.fc28", "rpm", "binary"},
	{"libtirpc", "1.0.3-3.rc2.fc28", "rpm", "source"},
	{"pkgconf-m4", "1.4.2-1.fc28", "rpm", "binary"},
	{"libreport", "2.9.5-1.fc28", "rpm", "source"},
	{"vim", "8.1.328-1.fc28", "rpm", "source"},
	{"file", "5.33-7.fc28", "rpm", "source"},
	{"shadow-utils", "4.6-1.fc28", "rpm", "source"},
	{"sqlite-libs", "3.22.0-4.fc28", "rpm", "binary"},
	{"setup", "2.11.4-1.fc28", "rpm", "source"},
	{"gcc", "8.1.1-5.fc28", "rpm", "source"},
	{"mpfr", "3.1.6-1.fc28", "rpm", "binary"},
	{"device-mapper", "1.02.146-5.fc28", "rpm", "binary"},
	{"p11-kit", "0.23.12-1.fc28", "rpm", "source"},
	{"fedora-release", "28-2", "rpm", "binary"},
	{"libnghttp2", "1.32.1-1.fc28", "rpm", "binary"},
	{"libcap-ng", "0.7.9-4.fc28", "rpm", "source"},
	{"iptables-libs", "1.6.2-3.fc28", "rpm", "binary"},
	{"audit-libs", "2.8.4-2.fc28", "rpm", "binary"},
	{"libsigsegv", "2.11-5.fc28", "rpm", "source"},
	{"rootfiles", "8.1-22.fc28", "rpm", "source"},
	{"kmod-libs", "25-2.fc28", "rpm", "binary"},
	{"lz4-libs", "1.8.1.2-4.fc28", "rpm", "binary"},
	{"libassuan", "2.5.1-3.fc28", "rpm", "source"},
	{"p11-kit", "0.23.12-1.fc28", "rpm", "binary"},
	{"nss-sysinit", "3.38.0-1.0.fc28", "rpm", "binary"},
	{"libcap-ng", "0.7.9-4.fc28", "rpm", "binary"},
	{"bash", "4.4.23-1.fc28", "rpm", "source"},
	{"pygobject3", "3.28.3-1.fc28", "rpm", "source"},
	{"dnf-yum", "2.7.5-12.fc28", "rpm", "binary"},
	{"nss-softokn", "3.38.0-1.0.fc28", "rpm", "binary"},
	{"expat", "2.2.5-3.fc28", "rpm", "binary"},
	{"libassuan", "2.5.1-3.fc28", "rpm", "binary"},
	{"libdb", "5.3.28-30.fc28", "rpm", "binary"},
	{"tar", "2:1.30-3.fc28", "rpm", "binary"},
	{"sed", "4.5-1.fc28", "rpm", "source"},
	{"libmetalink", "0.1.3-6.fc28", "rpm", "binary"},
	{"python-smartcols", "0.3.0-2.fc28", "rpm", "source"},
	{"systemd", "238-9.git0e0aa59.fc28", "rpm", "source"},
	{"python-iniparse", "0.4-30.fc28", "rpm", "source"},
	{"libsepol", "2.8-1.fc28", "rpm", "binary"},
	{"libattr", "2.4.48-3.fc28", "rpm", "binary"},
	{"python3-smartcols", "0.3.0-2.fc28", "rpm", "binary"},
	{"libdb", "5.3.28-30.fc28", "rpm", "source"},
	{"libmodulemd", "1.6.2-2.fc28", "rpm", "binary"},
	{"python3-hawkey", "0.11.1-3.fc28", "rpm", "binary"},
	{"dbus-libs", "1:1.12.10-1.fc28", "rpm", "binary"},
	{"chkconfig", "1.10-4.fc28", "rpm", "source"},
	{"libargon2", "20161029-5.fc28", "rpm", "binary"},
	{"openssl-pkcs11", "0.4.8-1.fc28", "rpm", "source"},
	{"libusbx", "1.0.22-1.fc28", "rpm", "source"},
	{"python3-setuptools", "39.2.0-6.fc28", "rpm", "binary"},
	{"chkconfig", "1.10-4.fc28", "rpm", "binary"},
	{"openldap", "2.4.46-3.fc28", "rpm", "source"},
	{"bzip2", "1.0.6-26.fc28", "rpm", "source"},
	{"npth", "1.5-4.fc28", "rpm", "source"},
	{"libtirpc", "1.0.3-3.rc2.fc28", "rpm", "binary"},
	{"util-linux", "2.32.1-1.fc28", "rpm", "binary"},
	{"nss", "3.38.0-1.0.fc28", "rpm", "source"},
	{"elfutils", "0.173-1.fc28", "rpm", "source"},
	{"libcomps", "0.1.8-11.fc28", "rpm", "source"},
	{"libxcrypt", "4.1.2-1.fc28", "rpm", "source"},
	{"gnupg2", "2.2.8-1.fc28", "rpm", "binary"},
	{"libdnf", "0.11.1-3.fc28", "rpm", "binary"},
	{"cracklib", "2.9.6-13.fc28", "rpm", "source"},
	{"libidn2", "2.0.5-1.fc28", "rpm", "source"},
	{"bzip2-libs", "1.0.6-26.fc28", "rpm", "binary"},
	{"json-c", "0.13.1-2.fc28", "rpm", "source"},
	{"gdbm", "1:1.14.1-4.fc28", "rpm", "binary"},
	{"pcre", "8.42-3.fc28", "rpm", "source"},
	{"systemd", "238-9.git0e0aa59.fc28", "rpm", "binary"},
	{"cryptsetup-libs", "2.0.4-1.fc28", "rpm", "binary"},
	{"dnf", "2.7.5-12.fc28", "rpm", "source"},
	{"ca-certificates", "2018.2.24-1.0.fc28", "rpm", "source"},
	{"libidn2", "2.0.5-1.fc28", "rpm", "binary"},
	{"libpsl", "0.20.2-2.fc28", "rpm", "binary"},
	{"gdbm-libs", "1:1.14.1-4.fc28", "rpm", "binary"},
	{"kmod", "25-2.fc28", "rpm", "source"},
	{"libreport-filesystem", "2.9.5-1.fc28", "rpm", "binary"},
	{"ima-evm-utils", "1.1-2.fc28", "rpm", "source"},
	{"nghttp2", "1.32.1-1.fc28", "rpm", "source"},
	{"cyrus-sasl-lib", "2.1.27-0.2rc7.fc28", "rpm", "binary"},
	{"libsolv", "0.6.35-1.fc28", "rpm", "binary"},
	{"cryptsetup", "2.0.4-1.fc28", "rpm", "source"},
	{"filesystem", "3.8-2.fc28", "rpm", "source"},
	{"libcap", "2.25-9.fc28", "rpm", "source"},
	{"libpsl", "0.20.2-2.fc28", "rpm", "source"},
	{"deltarpm", "3.6-25.fc28", "rpm", "source"},
	{"fedora-gpg-keys", "28-5", "rpm", "binary"},
	{"ima-evm-utils", "1.1-2.fc28", "rpm", "binary"},
	{"nss-tools", "3.38.0-1.0.fc28", "rpm", "binary"},
	{"libtasn1", "4.13-2.fc28", "rpm", "source"},
	{"elfutils-libelf", "0.173-1.fc28", "rpm", "binary"},
	{"device-mapper-libs", "1.02.146-5.fc28", "rpm", "binary"},
	{"gobject-introspection", "1.56.1-1.fc28", "rpm", "source"},
	{"publicsuffix-list", "20180514-1.fc28", "rpm", "source"},
	{"libcap", "2.25-9.fc28", "rpm", "binary"},
	{"librepo", "1.8.1-7.fc28", "rpm", "binary"},
	{"rpm-sign-libs", "4.14.1-9.fc28", "rpm", "binary"},
	{"coreutils-single", "8.29-7.fc28", "rpm", "binary"},
	{"libacl", "2.2.53-1.fc28", "rpm", "binary"},
	{"popt", "1.16-14.fc28", "rpm", "source"},
	{"libtasn1", "4.13-2.fc28", "rpm", "binary"},
	{"gawk", "4.2.1-1.fc28", "rpm", "source"},
	{"diffutils", "3.6-4.fc28", "rpm", "source"},
	{"libgpg-error", "1.31-1.fc28", "rpm", "source"},
	{"libdb-utils", "5.3.28-30.fc28", "rpm", "binary"},
	{"python3-iniparse", "0.4-30.fc28", "rpm", "binary"},
	{"acl", "2.2.53-1.fc28", "rpm", "binary"},
	{"libssh", "0.8.2-1.fc28", "rpm", "source"},
	{"python3-librepo", "1.8.1-7.fc28", "rpm", "binary"},
	{"gobject-introspection", "1.56.1-1.fc28", "rpm", "binary"},
	{"rpm", "4.14.1-9.fc28", "rpm", "source"},
	{"libgcrypt", "1.8.3-1.fc28", "rpm", "source"},
	{"curl", "7.59.0-6.fc28", "rpm", "source"},
	{"tzdata", "2018e-1.fc28", "rpm", "source"},
	{"krb5", "1.16.1-13.fc28", "rpm", "source"},
	{"librepo", "1.8.1-7.fc28", "rpm", "source"},
	{"python3-gpg", "1.10.0-4.fc28", "rpm", "binary"},
	{"nettle", "3.4-2.fc28", "rpm", "source"},
	{"libgcrypt", "1.8.3-1.fc28", "rpm", "binary"},
	{"python3", "3.6.6-1.fc28", "rpm", "binary"},
	{"python3-libcomps", "0.1.8-11.fc28", "rpm", "binary"},
	{"rpm-libs", "4.14.1-9.fc28", "rpm", "binary"},
	{"nspr", "4.19.0-1.fc28", "rpm", "binary"},
	{"argon2", "20161029-5.fc28", "rpm", "source"},
	{"tar", "1.30-3.fc28", "rpm", "source"},
	{"qrencode-libs", "3.4.4-5.fc28", "rpm", "binary"},
	{"gmp", "6.1.2-7.fc28", "rpm", "source"},
	{"libverto", "0.3.0-5.fc28", "rpm", "binary"},
	{"python3", "3.6.6-1.fc28", "rpm", "source"},
	{"libksba", "1.3.5-7.fc28", "rpm", "binary"},
	{"readline", "7.0-11.fc28", "rpm", "binary"},
	{"rpm-build-libs", "4.14.1-9.fc28", "rpm", "binary"},
	{"npth", "1.5-4.fc28", "rpm", "binary"},
	{"rootfiles", "8.1-22.fc28", "rpm", "binary"},
	{"rpm-plugin-systemd-inhibit", "4.14.1-9.fc28", "rpm", "binary"},
	{"systemd-libs", "238-9.git0e0aa59.fc28", "rpm", "binary"},
	{"nss-util", "3.38.0-1.0.fc28", "rpm", "binary"},
}

func TestRpmFeatureDetection(t *testing.T) {
	for _, test := range []featurefmt.TestCase{
		{
			"valid small case",
			map[string]string{"var/lib/rpm/Packages": "rpm/testdata/valid"},
			[]database.Feature{
				{"centos-release", "7-1.1503.el7.centos.2.8", "rpm", "binary"},
				{"filesystem", "3.2-18.el7", "rpm", "binary"},
				{"centos-release", "7-1.1503.el7.centos.2.8", "rpm", "source"},
				{"filesystem", "3.2-18.el7", "rpm", "source"},
			},
		},
		{
			"valid big case",
			map[string]string{"var/lib/rpm/Packages": "rpm/testdata/valid_big"},
			expectedBigCaseInfo,
		},
	} {
		featurefmt.RunTest(t, test, lister{}, rpm.ParserName)
	}
}

func TestParseSourceRPM(t *testing.T) {
	for _, test := range [...]struct {
		sourceRPM string

		expectedName    string
		expectedVersion string
		expectedErr     string
	}{
		// valid cases
		{"publicsuffix-list-20180514-1.fc28.src.rpm", "publicsuffix-list", "20180514-1.fc28", ""},
		{"libreport-2.9.5-1.fc28.src.rpm", "libreport", "2.9.5-1.fc28", ""},
		{"lua-5.3.4-10.fc28.src.rpm", "lua", "5.3.4-10.fc28", ""},
		{"crypto-policies-20180425-5.git6ad4018.fc28.src.rpm", "crypto-policies", "20180425-5.git6ad4018.fc28", ""},

		// invalid cases
		{"crypto-policies-20180425-5.git6ad4018.fc28.src.dpkg", "", "", "unexpected package type, expect: 'rpm', got: 'dpkg'"},
		{"crypto-policies-20180425-5.git6ad4018.fc28.debian-8.rpm", "", "", "unexpected package architecture, expect: 'src' or 'nosrc', got: 'debian-8'"},
		{"fc28.src.rpm", "", "", "unexpected termination while parsing 'Release Token'"},
		{"...", "", "", "unexpected package type, expect: 'rpm', got: ''"},

		// impossible case
		// This illustrates the limitation of this parser, it will not find the
		// error cased by extra '-' in the intended version/expect token. Based
		// on the documentation, this case should never happen and indicates a
		// corrupted rpm database.
		// actual expected: name="lua", version="5.3.4", release="10.fc-28"
		{"lua-5.3.4-10.fc-28.src.rpm", "lua-5.3.4", "10.fc-28", ""},
	} {
		name, version, release, _, err := parseSourceRPM(test.sourceRPM)
		if test.expectedErr != "" {
			require.EqualError(t, err, test.expectedErr)
			continue
		}

		require.Nil(t, err)
		require.Equal(t, test.expectedName, name)
		require.Equal(t, test.expectedVersion, version+"-"+release)
	}
}
