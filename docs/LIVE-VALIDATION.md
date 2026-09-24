# Integration validation summary

This file records capabilities exercised against a locally configured Incus daemon. These observations are evidence from one test environment, not a guarantee for every Incus version, host policy, image, network, or storage backend. The automated test suite uses mocks and does not replace these live checks.

## Exercised flows

- Created and removed disposable Ubuntu cloud VMs through both the backend and GTK wizard using a restricted user project, explicit storage, and explicit network configuration.
- Exercised VM start/stop, metrics, clone, snapshots, restore, full backup/export, and import. Backup archives include guest data and Incus agent credentials; the application creates a new archive with mode `0600`.
- Confirmed read-only and read-write host directory mounts from a guest. The wizard requires explicit mount selection, and read-only mounts rejected guest writes.
- Completed cloud-init installation of selected APT, Python, npm, Cargo, and Go software. A transient Go proxy/DNS failure recovered through the configured retry path; DNS behavior still depends on the host and guest network.
- Installed an XFCE guest desktop and confirmed that the display manager and graphical target started. Visual inspection of the VGA console and an interactive login were not completed.
- Exercised the restricted egress proxy policy with an allowed domain, a denied domain, blocked direct IPv4 egress, and unavailable external IPv6. This validates the tested bridge/helper setup only; operators must review their own firewall, bridge, and proxy configuration.
- Validated USB discovery and the explicit attachment path with mocks. A physical USB device was not attached during host validation to avoid disrupting host peripherals.

## Host integration boundaries

- The Incus user project remained restricted during the lifecycle checks. Any temporary project capability needed for a check was removed afterward.
- No test VM remains. No default NIC or mount is created implicitly. Incus configuration remains authoritative and can be changed outside the application.
- A host Docker forwarding policy can block traffic from a regular Incus bridge. The optional `packaging/isolatevm-docker-forward.*` files document a narrow operator-managed workaround; it is not installed or enabled by the IsolateVM package.
- The restricted egress helper and Squid are separate from the GTK process. Normal networking remains unfiltered; only the restricted policy applies the tested domain/port allowlist.

## Not verified or out of scope

- Visual login and an interactive session inside GNOME, KDE, or XFCE guests.
- Behavior on every Incus version, cloud image, storage driver, bridge topology, or host firewall.
- Secret injection, general GPU/PCI/serial passthrough, and non-Ubuntu guests.
- Host reboot persistence of any manually installed networking workaround.

Repeat live checks in a disposable Incus project before relying on them in a different environment. The project test suite and package build can be run without connecting to Incus; see [DEVELOPMENT.md](../DEVELOPMENT.md).
