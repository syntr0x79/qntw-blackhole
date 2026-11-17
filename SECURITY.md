# Security reports

Report a suspected defect with a minimal synthetic reproducer and the relevant
version. Do not attach production keys, client identifiers, connection journals,
packet captures, or live host inventories to public issues. Use GitHub's private
vulnerability reporting when available for sensitive details.

This repository contains defensive source classification and observation tools.
Treat runtime evidence and configurations as private. Shared-address false
positives, bounded capture, and the current nested HTTP-path limitation are
documented in the README. Reproducing a defect should use the disposable test
namespaces rather than a live firewall or VPN host.
