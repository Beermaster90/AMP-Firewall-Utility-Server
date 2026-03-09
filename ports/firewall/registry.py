from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from django.conf import settings
from django.db.utils import OperationalError, ProgrammingError
from django.utils.module_loading import import_string

from .base import FirewallProvider
from ports.models import FirewallProviderConfig


@dataclass(frozen=True)
class ProviderMeta:
    provider_id: str
    display_name: str
    local_provider: bool
    enabled: bool
    configured: bool
    supported: bool
    in_use: bool
    available: bool
    reason: str


def _provider_config_map() -> dict[str, FirewallProviderConfig]:
    try:
        return {c.provider_id: c for c in FirewallProviderConfig.objects.all()}
    except (OperationalError, ProgrammingError):
        return {}


def _load_provider(provider_id: str, config: dict | None = None) -> FirewallProvider:
    provider_path = settings.FIREWALL_PROVIDERS.get(provider_id)
    if not provider_path:
        raise KeyError(f"Unknown firewall provider '{provider_id}'")
    cls = import_string(provider_path)
    provider: FirewallProvider = cls(config=config or {})
    return provider


def _default_openwrt_config() -> dict:
    default_configs = getattr(settings, "FIREWALL_PROVIDER_DEFAULT_CONFIGS", {})
    raw = default_configs.get("openwrt", {})
    return raw if isinstance(raw, dict) else {}


def _provider_runtime_config(provider_id: str, cfg_row: FirewallProviderConfig | None) -> dict:
    if provider_id != "openwrt":
        return {}

    default_openwrt = _default_openwrt_config()
    default_auth = default_openwrt.get("auth", {})
    default_user = ""
    default_password = ""
    if isinstance(default_auth, dict):
        default_user = str(default_auth.get("username", "")).strip()
        default_password = str(default_auth.get("password", "")).strip()

    if cfg_row is None:
        return {
            "rpc_url": str(default_openwrt.get("rpc_url", "")).strip(),
            "auth": {"username": default_user, "password": default_password},
            "source_zone": str(default_openwrt.get("source_zone", "publicinternal")).strip() or "publicinternal",
            "forward_source_zone": str(default_openwrt.get("forward_source_zone", "wan")).strip() or "wan",
            "forward_dest_zone": str(default_openwrt.get("forward_dest_zone", "publicinternal")).strip() or "publicinternal",
            "forward_dest_ip": str(default_openwrt.get("forward_dest_ip", "")).strip(),
            "manage_mode": str(default_openwrt.get("manage_mode", "redirect")).strip() or "redirect",
            "aggressive_mode": str(default_openwrt.get("aggressive_mode", "1")).strip() or "1",
            "name_prefix": str(default_openwrt.get("name_prefix", "arksa-ports-web")).strip() or "arksa-ports-web",
            "display_prefix": str(default_openwrt.get("display_prefix", "AMP:")).strip() or "AMP:",
        }

    password = ""
    try:
        password = cfg_row.get_openwrt_password()
    except Exception:
        password = ""

    return {
        "rpc_url": str(cfg_row.openwrt_rpc_url).strip(),
        "auth": {
            "username": str(cfg_row.openwrt_username).strip(),
            "password": password,
        },
        "source_zone": str(cfg_row.openwrt_source_zone).strip() or "publicinternal",
        "forward_source_zone": str(cfg_row.openwrt_forward_source_zone).strip() or "wan",
        "forward_dest_zone": str(cfg_row.openwrt_forward_dest_zone).strip() or "publicinternal",
        "forward_dest_ip": str(cfg_row.openwrt_forward_dest_ip).strip(),
        "manage_mode": str(cfg_row.openwrt_manage_mode).strip() or "redirect",
        "aggressive_mode": "1" if bool(cfg_row.openwrt_aggressive_mode) else "0",
        "name_prefix": str(cfg_row.openwrt_name_prefix).strip() or "arksa-ports-web",
        "display_prefix": str(cfg_row.openwrt_display_prefix).strip() or "AMP:",
    }


def list_provider_meta() -> list[ProviderMeta]:
    config_by_id = _provider_config_map()
    items: list[ProviderMeta] = []
    for provider_id in settings.FIREWALL_PROVIDERS:
        cfg_row = config_by_id.get(provider_id)
        config = _provider_runtime_config(provider_id=provider_id, cfg_row=cfg_row)
        enabled = bool(cfg_row.enabled) if cfg_row else False
        provider = _load_provider(provider_id=provider_id, config=config)
        supported, support_reason = provider.is_supported()

        if provider.local_provider:
            # Local firewall providers are auto-detected; no manual config required.
            enabled = True
            configured = True
            in_use, in_use_reason = provider.is_in_use() if supported else (False, support_reason)
            available = supported and in_use
            reason = in_use_reason if supported else support_reason
        else:
            configured = enabled and provider.has_required_config()
            in_use = configured and supported
            available = in_use
            reason = support_reason
            if not enabled:
                reason = "Provider disabled in configuration."
            elif enabled and not provider.has_required_config():
                reason = "Missing required provider configuration values."

        items.append(
            ProviderMeta(
                provider_id=provider.provider_id,
                display_name=provider.display_name,
                local_provider=provider.local_provider,
                enabled=enabled,
                configured=configured,
                supported=supported,
                in_use=in_use,
                available=available,
                reason=reason,
            )
        )
    return items


def get_provider(provider_id: str, require_available: bool = False) -> FirewallProvider:
    config_by_id = _provider_config_map()
    cfg_row = config_by_id.get(provider_id)
    config = _provider_runtime_config(provider_id=provider_id, cfg_row=cfg_row)
    provider = _load_provider(provider_id=provider_id, config=config)
    if require_available:
        supported, support_reason = provider.is_supported()
        if provider.local_provider:
            if not supported:
                raise RuntimeError(f"Provider '{provider_id}' is not installed on localhost: {support_reason}")
            in_use, in_use_reason = provider.is_in_use()
            if not in_use:
                raise RuntimeError(f"Provider '{provider_id}' is not active/in use: {in_use_reason}")
        else:
            enabled = bool(cfg_row.enabled) if cfg_row else False
            configured = enabled and provider.has_required_config()
            if not configured:
                raise RuntimeError(f"Provider '{provider_id}' is not configured/enabled.")
            if not supported:
                raise RuntimeError(f"Provider '{provider_id}' is not available on localhost: {support_reason}")
    return provider


def provider_choices(only_available: bool = True, local_only: bool = False) -> Iterable[tuple[str, str]]:
    for meta in list_provider_meta():
        if local_only and not meta.local_provider:
            continue
        if only_available and not meta.available:
            continue
        yield (meta.provider_id, meta.display_name)
