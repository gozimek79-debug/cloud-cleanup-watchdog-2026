# Cloud cleanup watchdog

A small, generic Hetzner Cloud cleanup watchdog for one disposable server in one project. This public repository contains no project identifiers, server identifiers, credentials, backup data, or private operational documentation.

The scheduled workflow runs on a standard GitHub-hosted runner. It does not run on pull requests. It first runs offline safety tests. In `offline` mode it makes no cloud requests. In active mode it reads `HCLOUD_TOKEN` and optional `TARGET_MANIFEST` from protected repository secrets. An empty manifest performs a read-only inventory check and fails if billable resources already exist. An armed manifest is authenticated with an HMAC keyed by the project token and contains the exact server ID, creation time, IPv4 ID, and six-hour cleanup time.

The token must be created in the intended empty Hetzner project. Hetzner API tokens are project-scoped. A successful preflight alone does not prove project identity; binding requires the token to see the exact server after creation. Deletion is never attempted before the six-hour target. The watchdog checks that the server and billable project resources disappear, and deletes only a bound leftover Primary IPv4 that is unassigned. All other unexpected resources cause failure and require human investigation.

Scheduled workflows can be delayed or missed. Keep a separate local controller and an independent alert/recovery procedure. A green workflow run is not proof of a billing outcome; confirm the provider inventory and final charge.

Public workflow output contains only generic status codes. Do not upload audit logs, manifests, API tokens, or infrastructure evidence to this repository.

