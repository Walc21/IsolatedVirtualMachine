#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stage_dir="$(mktemp -d)"
trap 'rm -rf "$stage_dir"' EXIT
mkdir -p "$stage_dir/DEBIAN" "$stage_dir/usr/lib/python3/dist-packages" "$stage_dir/usr/bin" "$stage_dir/usr/lib/isolatevm/guest" \
  "$stage_dir/usr/share/applications" "$stage_dir/usr/share/icons/hicolor/scalable/apps" \
  "$stage_dir/usr/share/doc/isolatevm/docs" "$stage_dir/usr/share/doc/isolatevm/host-ops" \
  "$stage_dir/usr/share/polkit-1/actions" "$stage_dir/usr/lib/systemd/system" "$project_dir/dist"
cp -a "$project_dir/isolatevm" "$stage_dir/usr/lib/python3/dist-packages/"
find "$stage_dir/usr/lib/python3/dist-packages/isolatevm" -type d -name __pycache__ -prune -exec rm -rf {} +
cat > "$stage_dir/usr/bin/isolatevm" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -m isolatevm "$@"
EOF
chmod 0755 "$stage_dir/usr/bin/isolatevm"
cp "$project_dir/packaging/org.isolatevm.IsolateVM.desktop" "$stage_dir/usr/share/applications/"
cp "$project_dir/packaging/org.isolatevm.IsolateVM.svg" "$stage_dir/usr/share/icons/hicolor/scalable/apps/"
cp "$project_dir/README.md" "$project_dir/ARCHITECTURE.md" "$project_dir/SECURITY.md" \
   "$project_dir/DEVELOPMENT.md" "$project_dir/PACKAGING.md" \
   "$stage_dir/usr/share/doc/isolatevm/"
cp "$project_dir/docs/MANIFEST.md" "$project_dir/docs/LIVE-VALIDATION.md" \
   "$project_dir/docs/host-init-preseed.yaml" "$stage_dir/usr/share/doc/isolatevm/docs/"
cp "$project_dir/packaging/isolatevm-docker-forward.sh" \
   "$project_dir/packaging/isolatevm-docker-forward.service" \
   "$stage_dir/usr/share/doc/isolatevm/host-ops/"
cp "$project_dir/packaging/isolatevm-egress-helper.py" "$stage_dir/usr/lib/isolatevm/isolatevm-egress-helper"
cp "$project_dir/packaging/guest/isolatevm-inject-secrets.py" "$project_dir/packaging/guest/isolatevm-run" \
   "$project_dir/packaging/guest/isolatevm-copy-files.py" "$project_dir/packaging/guest/isolatevm-setup-devops" \
  "$stage_dir/usr/lib/isolatevm/guest/"
cp "$project_dir/packaging/isolatevm-egress@.service" "$stage_dir/usr/lib/systemd/system/"
cp "$project_dir/packaging/isolatevm-egress-firewall.service" "$stage_dir/usr/lib/systemd/system/"
cp "$project_dir/packaging/org.isolatevm.egress.policy" "$stage_dir/usr/share/polkit-1/actions/"
cat > "$stage_dir/DEBIAN/control" <<'EOF'
Package: isolatevm
Version: 0.3.8
Section: admin
Priority: optional
Architecture: all
Maintainer: IsolateVM Project <local@localhost>
Depends: python3 (>= 3.11), python3-gi, python3-yaml, python3-secretstorage, gir1.2-gtk-4.0, gir1.2-adw-1, gir1.2-vte-3.91, nftables, squid, polkitd
Recommends: incus-client
Suggests: virt-viewer
Description: Local graphical manager for Incus virtual machines
 A deny-by-default desktop interface for creating and managing Incus VMs.
EOF
cat > "$stage_dir/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = remove ]; then
  active=0
  if [ -e /var/lib/isolatevm/egress/state.json ] && ! /usr/bin/python3 - /var/lib/isolatevm/egress/state.json <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as state_file:
        state = json.load(state_file)
except Exception:
    raise SystemExit(2)
raise SystemExit(0 if isinstance(state, dict) and not state else 1)
PY
  then active=1
  fi
  if [ -e /etc/systemd/system/incus.service.d/10-isolatevm-egress.conf ] || \
     [ -e /etc/systemd/system/snap.incus.daemon.service.d/10-isolatevm-egress.conf ]; then
    active=1
  fi
  if [ "$active" -ne 0 ]; then
    echo "Remova as VMs com rede restrita no IsolateVM antes de desinstalar; o firewall de boot protege essas VMs." >&2
    exit 1
  fi
fi
exit 0
EOF
cat > "$stage_dir/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = configure ] && [ -s /var/lib/isolatevm/egress/state.json ]; then
  /usr/lib/isolatevm/isolatevm-egress-helper install-firewall-guard
fi
exit 0
EOF
find "$stage_dir" -type d -exec chmod 0755 {} +
find "$stage_dir" -type f -exec chmod 0644 {} +
chmod 0755 "$stage_dir/usr/bin/isolatevm"
chmod 0755 "$stage_dir/usr/lib/isolatevm/isolatevm-egress-helper"
chmod 0755 "$stage_dir/DEBIAN/prerm"
chmod 0755 "$stage_dir/DEBIAN/postinst"
dpkg-deb --root-owner-group --build "$stage_dir" "$project_dir/dist/isolatevm_0.3.8_all.deb"
