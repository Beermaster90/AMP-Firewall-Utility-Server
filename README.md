# AMP Firewall Utility Server

Django web UI for discovering AMP instance ports and managing firewall rules through pluggable providers.

## Get The Code

Clone the repository:

```bash
git clone <repo-url>
cd arksa-ports-web
```

Update an existing checkout:

```bash
git pull --ff-only
```

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
git clone <repo-url>
cd arksa-ports-web
./install.sh
```

`install.sh` creates the virtual environment in `.venv`.

For manual Django commands, activate it first:

```bash
source .venv/bin/activate
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
source .venv/bin/activate
./run-ports-web.sh
```

Open: `http://127.0.0.1:8001/`

You can also open it from your local network using the host LAN IP, for example:
- `http://192.168.x.x:8001/`

Do **not** expose this service directly to the public internet.

## Run As A Service

This repository includes a `systemd` unit template that runs the app as the current project user and restarts it automatically if it exits.

Files:

- `run-ports-web-service.sh`
- `arksa-ports-web.service`
- `install-systemd-service.sh`

Install and start it:

```bash
sudo ./install-systemd-service.sh
```

Common service commands:

```bash
sudo systemctl start arksa-ports-web.service
sudo systemctl status arksa-ports-web.service
sudo systemctl restart arksa-ports-web.service
sudo systemctl stop arksa-ports-web.service
sudo systemctl enable arksa-ports-web.service
sudo systemctl disable arksa-ports-web.service
journalctl -u arksa-ports-web.service -n 100 --no-pager
journalctl -u arksa-ports-web.service -f
```

When to restart the service:

```bash
sudo systemctl restart arksa-ports-web.service
```

Restart it after:

- changing Python code
- changing templates
- changing `.env`
- reinstalling dependencies

When you pull new code:

```bash
git pull --ff-only
source .venv/bin/activate
python manage.py migrate
sudo systemctl restart arksa-ports-web.service
```

Full service lifecycle example:

```bash
sudo ./install-systemd-service.sh
sudo systemctl status arksa-ports-web.service
sudo systemctl restart arksa-ports-web.service
sudo systemctl stop arksa-ports-web.service
sudo systemctl start arksa-ports-web.service
sudo systemctl disable arksa-ports-web.service
```

Notes:

- The install script resolves the runtime user automatically from `sudo` or the project directory owner
- It uses `<project-dir>/.env` as an optional environment file
- It listens on `0.0.0.0:8001` by default
- It uses `runserver --noreload` so `systemd` sees a single stable process

## Configuration Model

- AMP and firewall provider configuration are managed from the UI:
  - `http://127.0.0.1:8001/providers`
- AMP connection (`url`, `username`, `password`) is configured in UI.
- AMP password is stored encrypted in DB and decrypted only when AMP API calls are made.
- Localhost providers (`ufw`, `iptables`) are auto-detected.
- OpenWrt provider is configured using UI fields (no JSON config editing).
- OpenWrt password is stored encrypted in DB and decrypted only when provider calls are executed.

## Security Notes

- All application routes now require Django authentication. Create a superuser before first use:

```bash
source .venv/bin/activate
python manage.py createsuperuser
```

- Safer defaults are now enabled:
  - `DJANGO_DEBUG=0` by default
  - `DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]` by default
- AMP and OpenWrt management URLs are restricted to `http://` or `https://`, with no embedded credentials, no query string, and only private/loopback/link-local destinations.
- You can further pin allowed management hosts with:
  - `AMP_ALLOWED_HOSTS=host1,host2`
  - `OPENWRT_ALLOWED_HOSTS=host1,host2`
- Local firewall commands use an execution timeout. Override if needed with:
  - `FIREWALL_COMMAND_TIMEOUT=10`
- Firewall actions are validated against the discovered AMP snapshot, so tampering with hidden form fields cannot open arbitrary ports.

## Security Configuration Examples

These values are read from environment variables. The simplest way to use them is to create a `.env` file in the project root.

Example:

```env
DJANGO_DEBUG=0
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]

AMP_ALLOWED_HOSTS=127.0.0.1
OPENWRT_ALLOWED_HOSTS=192.168.1.1

FIREWALL_COMMAND_TIMEOUT=10
```

### Scenario 1: Localhost-only

Use this when you only open the web UI on the same machine where this app is running.

```env
DJANGO_DEBUG=0
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]

AMP_ALLOWED_HOSTS=127.0.0.1,localhost
OPENWRT_ALLOWED_HOSTS=

FIREWALL_COMMAND_TIMEOUT=10
```

- Open the UI with `http://127.0.0.1:8001/`
- If AMP is local, use an AMP URL like `http://127.0.0.1:8080`

### Scenario 2: Access from your LAN

Use this when the web UI is on one machine and you open it from another machine on your home/server network.

```env
DJANGO_DEBUG=0
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,192.168.1.50

AMP_ALLOWED_HOSTS=192.168.1.10
OPENWRT_ALLOWED_HOSTS=

FIREWALL_COMMAND_TIMEOUT=10
```

- Replace `192.168.1.50` with the IP of the machine running this web app
- Replace `192.168.1.10` with the AMP server IP
- Open the UI with `http://192.168.1.50:8001/`
- In the provider page, AMP URL can be `http://192.168.1.10:8080`

### Scenario 3: LAN access with OpenWrt enabled

Use this when AMP is on your LAN and firewall management happens through an OpenWrt router.

```env
DJANGO_DEBUG=0
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,192.168.1.50

AMP_ALLOWED_HOSTS=192.168.1.10
OPENWRT_ALLOWED_HOSTS=192.168.1.1

FIREWALL_COMMAND_TIMEOUT=10
```

- Replace `192.168.1.50` with the IP of the machine running this web app
- Replace `192.168.1.10` with the AMP server IP
- Replace `192.168.1.1` with the OpenWrt router IP
- AMP URL can be `http://192.168.1.10:8080`
- OpenWrt RPC URL can be `http://192.168.1.1/ubus`

## What Each Setting Means

- `DJANGO_DEBUG=0`
  Keeps Django debug pages disabled. Leave this as `0` unless you are actively debugging locally.

- `DJANGO_ALLOWED_HOSTS=host1,host2`
  Controls which hostnames or IPs are allowed to reach this web app.
  If you browse to `http://192.168.1.50:8001/`, then `192.168.1.50` must be listed here.

- `AMP_ALLOWED_HOSTS=host1,host2`
  Restricts which AMP hosts this app is allowed to connect to.
  If AMP runs at `http://192.168.1.10:8080`, then `192.168.1.10` should be listed here.

- `OPENWRT_ALLOWED_HOSTS=host1,host2`
  Restricts which OpenWrt hosts this app is allowed to connect to.
  If OpenWrt RPC is `http://192.168.1.1/ubus`, then `192.168.1.1` should be listed here.

- `FIREWALL_COMMAND_TIMEOUT=10`
  Maximum seconds a local `iptables` or `ufw` command is allowed to run before it is aborted.

## Allowed and Rejected URL Examples

Allowed:

- `http://127.0.0.1:8080`
- `http://192.168.1.10:8080`
- `http://192.168.1.1/ubus`

Rejected:

- `https://user:pass@192.168.1.1/ubus`
- `http://example.com/ubus`
- `http://1.2.3.4/ubus`
- `http://192.168.1.1/ubus?test=1`

Rules enforced by URL validation:

- Only `http://` and `https://` are allowed
- Username/password inside the URL are not allowed
- Query strings and fragments are not allowed
- Targets must resolve to private, loopback, or link-local IP addresses

## Hidden Field Protection

The UI sends port actions using normal HTML form fields, but the server no longer trusts those values directly.

When a user clicks enable/disable:

- The requested instance/port/protocol must exist in the current discovered AMP snapshot
- If it does not exist, the firewall action is rejected
- This prevents someone from editing browser form data and opening arbitrary ports manually

## Status Semantics

- `Open`: matching enabled allow/forward rule exists.
- `Disabled`: matching managed rule exists but is disabled.
- `Closed`: no matching usable rule.
- `Unknown`: provider cannot determine state.

## Extending Providers

- Implement a new class using `FirewallProvider` contract in `ports/firewall/base.py`.
- Add it to `FIREWALL_PROVIDERS` in `portadmin/settings.py`.
