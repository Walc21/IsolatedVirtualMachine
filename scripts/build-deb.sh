#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stage_dir="$(mktemp -d)"
trap 'rm -rf "$stage_dir"' EXIT
mkdir -p "$stage_dir/DEBIAN" "$stage_dir/usr/lib/python3/dist-packages" "$stage_dir/usr/bin" "$stage_dir/usr/lib/isolatevm" \
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
cp "$project_dir/packaging/isolatevm-egress@.service" "$stage_dir/usr/lib/systemd/system/"
cp "$project_dir/packaging/org.isolatevm.egress.policy" "$stage_dir/usr/share/polkit-1/actions/"
cat > "$stage_dir/DEBIAN/control" <<'EOF'
Package: isolatevm
Version: 0.2.2
Section: admin
Priority: optional
Architecture: all
Maintainer: IsolateVM Project <local@localhost>
Depends: python3 (>= 3.11), python3-gi, python3-yaml, gir1.2-gtk-4.0, gir1.2-adw-1, nftables, squid, polkitd
Recommends: incus-client
Suggests: virt-viewer
Description: Local graphical manager for Incus virtual machines
 A deny-by-default desktop interface for creating and managing Incus VMs.
EOF
find "$stage_dir" -type d -exec chmod 0755 {} +
find "$stage_dir" -type f -exec chmod 0644 {} +
chmod 0755 "$stage_dir/usr/bin/isolatevm"
chmod 0755 "$stage_dir/usr/lib/isolatevm/isolatevm-egress-helper"
dpkg-deb --root-owner-group --build "$stage_dir" "$project_dir/dist/isolatevm_0.2.2_all.deb"
