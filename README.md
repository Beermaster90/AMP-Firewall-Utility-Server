# AMP Firewall Utility Server

Django web UI for discovering AMP instance ports and managing firewall rules through pluggable providers.

## Intended Deployment

- This service is intended to run on the same host machine where AMP is running.
- Local providers (`iptables`, `ufw`) execute commands on the local host, so running remotely will not manage the AMP host firewall unless you use a remote provider (for example OpenWrt RPC).

## What It Does

- Reads instance + port data from AMP.
- Keeps a local snapshot in sync (adds new, updates existing, removes deleted).
- Shows per-port firewall status.
- Supports single and bulk actions (enable/disable).
- Supports OpenWrt orphan `AMP:` rule cleanup (disable/delete, including bulk delete).

## Setup

```bash
./install.sh
```

## Sudo Requirements (iptables/ufw)

Local firewall providers call commands through `sudo -n`, so the runtime user must have passwordless sudo for those binaries.

1. Find the runtime user (the account running `run-ports-web.sh` / Django).
2. Create a sudoers file using `visudo`:

```bash
sudo visudo -f /etc/sudoers.d/amp-firewall-web
```

3. Add rules (replace `AMPWEBUSER` with your runtime user):

```sudoers
AMPWEBUSER ALL=(root) NOPASSWD: /usr/sbin/iptables
AMPWEBUSER ALL=(root) NOPASSWD: /usr/sbin/ufw
```

4. Ensure file permissions are correct:

```bash
sudo chmod 440 /etc/sudoers.d/amp-firewall-web
```

## Run

```bash
./run-ports-web.sh
```

Open: `http://127.0.0.1:8001/`

You can also open it from your local network using the host LAN IP, for example:
- `http://192.168.x.x:8001/`

Do **not** expose this service directly to the public internet. It is not hardened/validated as an internet-facing secure service.

## Configuration Model

- AMP and firewall provider configuration are managed from the UI:
  - `http://127.0.0.1:8001/providers`
- AMP connection (`url`, `username`, `password`) is configured in UI.
- AMP password is stored encrypted in DB and decrypted only when AMP API calls are made.
- Localhost providers (`ufw`, `iptables`) are auto-detected.
- OpenWrt provider is configured using UI fields (no JSON config editing).
- OpenWrt password is stored encrypted in DB and decrypted only when provider calls are executed.

## Status Semantics

- `Open`: matching enabled allow/forward rule exists.
- `Disabled`: matching managed rule exists but is disabled.
- `Closed`: no matching usable rule.
- `Unknown`: provider cannot determine state.

## Extending Providers

- Implement a new class using `FirewallProvider` contract in `ports/firewall/base.py`.
- Add it to `FIREWALL_PROVIDERS` in `portadmin/settings.py`.
