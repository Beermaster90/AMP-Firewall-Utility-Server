# AMP Firewall Utility Server

Django web UI for discovering AMP instance ports and managing firewall rules through pluggable providers.

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

## Run

```bash
./run-ports-web.sh
```

Open: `http://127.0.0.1:8001/`

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
