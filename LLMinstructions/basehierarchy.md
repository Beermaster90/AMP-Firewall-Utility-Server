# Base Hierarchy Instructions (AI)

This file defines the project structure and ownership so AI can modify the correct files quickly and consistently.

## Purpose
- Use this as the first map before making changes.
- Keep updates scoped to the correct layer (settings, models, services, providers, views, templates).
- Prevent logic from being added in the wrong place.

## Top-Level Layout
- `manage.py`: Django management entrypoint.
- `run-ports-web.sh`: Runtime launcher and bind host/port defaults.
- `install.sh`: Local setup bootstrap.
- `requirements.txt`: Python dependencies.
- `README.md`: Human-facing documentation.
- `portadmin/`: Django project config (settings, root urls, asgi/wsgi).
- `ports/`: Main app for AMP discovery + firewall management.
- `LLMinstructions/`: AI-only operational instructions and conventions.

## Django Project Layer (`portadmin/`)
- `portadmin/settings.py`
  - Global app config, provider registry paths, runtime flags.
  - Add environment flags here when feature toggles are needed.
- `portadmin/urls.py`
  - Root routing; includes app urls.

## App Layer (`ports/`)
- `ports/models.py`
  - DB schema: discovered instances/ports, provider config, AMP config.
- `ports/migrations/`
  - Schema evolution; always add migration for model changes.
- `ports/security.py`
  - Encryption/decryption for secrets stored in DB.
- `ports/forms.py`
  - Input validation for UI actions and filters.
- `ports/views.py`
  - Request orchestration and response rendering.
  - Keep heavy external API details in services, not in views.
- `ports/urls.py`
  - App routes (index/actions/providers/progress).
- `ports/tests.py`
  - Add or extend tests for behavior changes.

## Service Layer (`ports/services/`)
- `amp_ports.py`
  - AMP API integration and instance/port collection.
  - Parsing, compatibility handling, progress callbacks.
- `snapshot_sync.py`
  - Synchronization from collected runtime data into DB snapshot.

## Firewall Domain Layer (`ports/firewall/`)
- `base.py`
  - Core contract (`FirewallProvider`) and shared result/target/status types.
- `registry.py`
  - Provider loading, availability checks, runtime config assembly.
- `providers/`
  - Concrete provider implementations (`ufw`, `iptables`, `openwrt`, `noop`).
  - `shell_base.py` for local shell-command provider shared behavior.

## UI Layer
- `ports/templates/ports/index.html`
  - Main UI, bulk actions, provider/filter forms, JS interactions.
- `ports/templates/ports/providers.html`
  - Provider and AMP credential management UI.
- `ports/static/ports/`
  - Static assets (if added later).

## AI Change Routing Rules
- AMP fetch/parsing issue -> `ports/services/amp_ports.py` first.
- DB snapshot mismatch issue -> `ports/services/snapshot_sync.py` and `ports/models.py`.
- Provider behavior issue -> `ports/firewall/providers/<provider>.py` and possibly `registry.py`.
- Form validation issue -> `ports/forms.py`.
- UX behavior issue -> template JS/CSS in `ports/templates/ports/*.html`.
- Endpoint/routing issue -> `ports/urls.py` and `portadmin/urls.py`.

## Mandatory AI Maintenance Rules
When adding/removing/moving major files or modules:
1. Update this file in the same change.
2. Update `LLMinstructions/interface-generation.md` if provider contracts or generation rules changed.
3. If new domain areas are added, create new `LLMinstructions/<topic>.md` instruction files.
4. Keep these docs concise and implementation-accurate (no stale references).

## Documentation Sync Checklist (AI)
- [ ] New file/folder appears in correct section above.
- [ ] Ownership/layer responsibility remains clear.
- [ ] Cross-file dependencies (e.g., provider registry path) are still valid.
- [ ] Any new feature toggle or endpoint is documented.
