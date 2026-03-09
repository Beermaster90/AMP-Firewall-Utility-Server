# Interface / Provider Generation Instructions (AI)

This file defines how AI should create or modify firewall provider implementations so all providers follow the same logic model.

## Scope
Applies to:
- `ports/firewall/base.py`
- `ports/firewall/registry.py`
- `ports/firewall/providers/*.py`
- provider-specific config fields in models/forms/templates/settings when needed.

## Contract Baseline
Every provider must conform to `FirewallProvider` in `ports/firewall/base.py`:
- Required fields: `provider_id`, `display_name`
- Required methods:
  - `apply(action, target) -> FirewallActionResult`
  - `get_status(target) -> FirewallStatusResult`
- Optional behavior:
  - `has_required_config()`
  - `is_supported()`
  - `is_in_use()`

## Provider Design Rules
1. Keep provider-specific logic inside provider file only.
2. Return structured result objects; do not raise for normal operational failures.
3. Error messages must be actionable and short.
4. `get_status` must map to one of:
   - `Open`
   - `Disabled`
   - `Closed`
   - `Unknown`
5. Respect dry-run behavior through existing runtime switches when applicable.
6. Avoid duplicating parsing logic that can be shared (use base classes such as `shell_base.py`).

## Naming and File Rules
- File name: `ports/firewall/providers/<provider_id>.py`
- Class name: `<ProviderName>FirewallProvider`
- `provider_id` must match registry/settings key.
- `display_name` should be user-friendly and stable.

## Registration Rules
When adding a provider:
1. Add provider class file under `ports/firewall/providers/`.
2. Register import path in `portadmin/settings.py` (`FIREWALL_PROVIDERS`).
3. Ensure `ports/firewall/registry.py` can build runtime config for it.
4. Add provider config model fields/forms/UI only if truly needed.
5. Ensure provider availability appears correctly in providers UI.

## Local Shell Providers (ufw/iptables style)
- Prefer inheriting from `ShellCommandFirewallProvider`.
- Implement:
  - command builder for enable/disable
  - status command
  - parser for command output
- Treat command-not-found and command-failure distinctly in messages.
- Keep protocol normalization consistent (`tcp`/`udp`).

## Remote/API Providers (openwrt style)
- Validate required config thoroughly.
- Keep auth/session handling isolated in helper methods.
- Separate read/status operations from mutate/apply operations.
- Preserve idempotency:
  - enable should not duplicate existing managed rule
  - disable should gracefully handle already-disabled/absent cases

## Common Logic Matching Requirements
All providers should behave consistently for identical targets:
- Same target shape (`instance_name`, `instance_friendly_name`, `description`, `port`, `protocol`)
- Same action semantics (`enable` adds/activates, `disable` removes/deactivates per provider model)
- Same status interpretation hierarchy (exact match beats default policy inference)
- Similar wording style in user-visible messages.

## AI Auto-Update Requirements
Whenever interface/provider behavior changes:
1. Update this instruction file in same commit/patch.
2. If new provider family is introduced (e.g., nftables/cloud firewall), add a dedicated instruction doc under `LLMinstructions/`.
3. Keep examples and rules aligned with actual base contract in `ports/firewall/base.py`.
4. Remove outdated assumptions immediately.

## Minimal Provider Implementation Checklist (AI)
- [ ] Class compiles and imports cleanly.
- [ ] Provider can be loaded by registry.
- [ ] `is_supported()` and `is_in_use()` reflect real runtime state.
- [ ] `apply()` and `get_status()` return contract objects in all branches.
- [ ] No unhandled exceptions leak to UI in expected failure paths.
- [ ] Behavior verified with at least one realistic command/API response path.
