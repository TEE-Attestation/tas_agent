# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
Name:           tas-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        TEE Attestation Service Agent for LUKS unlock

License:        MIT
URL:            https://github.com/hpe/tas_agent
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo rust pkg-config openssl-devel
Requires:       systemd cryptsetup

%description
Agent for fetching LUKS encryption keys from the TEE Attestation Service
using hardware-based TEE attestation (AMD SEV-SNP, Intel TDX).
Integrates with systemd ask-password for automatic LUKS volume unlock
during boot, with TTY fallback on failure.

# ---------------------------------------------------------------------------
%package dracut
Summary:        TAS Agent dracut integration
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       dracut
Requires:       dracut-network

%description dracut
Dracut module for integrating TAS Agent into dracut-based initrd images
for automatic LUKS unlock during early boot.

# ---------------------------------------------------------------------------
%prep
%autosetup

%build
cargo build --release --features askpass

%check
cargo test --features askpass

%install
# --- tas-agent (core) ---
install -Dm755 target/release/tas_agent %{buildroot}/usr/sbin/tas_agent
install -Dm755 scripts/tas-luks-bind %{buildroot}/usr/sbin/tas-luks-bind
install -Dm644 config/config.toml.sample %{buildroot}/etc/tas_agent/config.toml
install -Dm600 config/api-key.sample %{buildroot}/etc/tas_agent/api-key
install -Dm644 scripts/systemd/tas-agent-askpass.service %{buildroot}/usr/lib/systemd/system/tas-agent-askpass.service
install -Dm644 scripts/systemd/tas-agent-askpass.path %{buildroot}/usr/lib/systemd/system/tas-agent-askpass.path
install -Dm644 scripts/systemd/tas-agent-network.service %{buildroot}/usr/lib/systemd/system/tas-agent-network.service
install -Dm644 scripts/systemd/modules-load.d/tas-agent.conf %{buildroot}/etc/modules-load.d/tas-agent.conf

# --- tas-agent-dracut ---
install -Dm755 scripts/dracut/module-setup.sh %{buildroot}/usr/lib/dracut/modules.d/50tas-agent/module-setup.sh
install -Dm755 scripts/dracut/tas-net-setup.sh %{buildroot}/usr/lib/dracut/modules.d/50tas-agent/tas-net-setup.sh

# ---------------------------------------------------------------------------
%files
%license LICENSE.md
/usr/sbin/tas_agent
/usr/sbin/tas-luks-bind
%dir /etc/tas_agent
%config(noreplace) /etc/tas_agent/config.toml
%config(noreplace) %attr(600,root,root) /etc/tas_agent/api-key
/usr/lib/systemd/system/tas-agent-askpass.service
/usr/lib/systemd/system/tas-agent-askpass.path
/usr/lib/systemd/system/tas-agent-network.service
%config(noreplace) /etc/modules-load.d/tas-agent.conf

%files dracut
/usr/lib/dracut/modules.d/50tas-agent/module-setup.sh
/usr/lib/dracut/modules.d/50tas-agent/tas-net-setup.sh

# ---------------------------------------------------------------------------
%post
systemctl daemon-reload
systemctl enable tas-agent-askpass.path || true

%preun
systemctl disable tas-agent-askpass.path || true
systemctl stop tas-agent-askpass.path tas-agent-askpass.service || true

%postun
systemctl daemon-reload || true

%post dracut
if command -v dracut >/dev/null 2>&1; then
    echo "Rebuilding initramfs with TAS agent dracut module..."
    dracut --force || true
fi
echo ""
echo "TAS Agent dracut module installed."
echo "Ensure /etc/tas_agent/config.toml and /etc/tas_agent/api-key are configured."
echo "Add '_netdev' to your /etc/crypttab LUKS entries."
echo "Add 'rd.neednet=1 ip=dhcp' to kernel cmdline (grubby --update-kernel=ALL --args='rd.neednet=1 ip=dhcp')."
echo "Run 'dracut --force' if the initramfs was not rebuilt automatically."
echo ""

%preun dracut
if command -v dracut >/dev/null 2>&1; then
    dracut --force || true
fi

%postun dracut
if [ "$1" -eq 0 ] && command -v dracut >/dev/null 2>&1; then
    dracut --force || true
fi

# ---------------------------------------------------------------------------
%changelog
* Thu Apr 09 2026 TAS <https://github.com/hpe/tas_agent> - 0.1.0-1
- Add tas-luks-bind helper script
- Dracut module subpackage for initrd integration
- Initial release with systemd askpass integration
