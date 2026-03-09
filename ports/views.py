from __future__ import annotations

import json
import queue
import threading
from urllib.parse import urlencode

from django.contrib import messages
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse

from .firewall.base import FirewallAction, FirewallPortStatus, FirewallPortTarget
from .firewall.registry import get_provider, list_provider_meta, provider_choices
from .forms import (
    BulkPortActionForm,
    OrphanRuleActionForm,
    OrphanRuleBulkActionForm,
    PortActionForm,
    PortListFilterForm,
)
from .models import AMPConnectionConfig, DiscoveredInstance, DiscoveredPort, FirewallProviderConfig
from .services.amp_ports import AMPPortCollector, InstancePort, InstancePorts, test_amp_connection
from .services.snapshot_sync import sync_discovered_data


def _build_return_query_from_source(source: dict[str, str]) -> str:
    query: dict[str, str] = {}
    provider_back = str(source.get("return_provider_id", "")).strip()
    include_ads_back = str(source.get("return_include_ads", "")).strip().lower()
    filter_field_back = str(source.get("return_filter_field", "")).strip()
    filter_query_back = str(source.get("return_filter_query", "")).strip()
    active_only_back = str(source.get("return_active_only", "")).strip().lower()
    if provider_back:
        query["provider_id"] = provider_back
    if include_ads_back in {"1", "true", "on", "yes"}:
        query["include_ads"] = "on"
    if filter_field_back in {"name", "description"}:
        query["filter_field"] = filter_field_back
    if filter_query_back:
        query["filter_query"] = filter_query_back
    if active_only_back in {"1", "true", "on", "yes"}:
        query["active_only"] = "on"
    if query:
        return f"?{urlencode(query)}"
    return ""


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _load_snapshot_instances(include_ads: bool = False) -> list[InstancePorts]:
    rows: list[InstancePorts] = []
    db_instances = DiscoveredInstance.objects.prefetch_related("ports").all()
    for inst in db_instances:
        if not include_ads and AMPPortCollector._is_ads(module=str(inst.module), instance_name=str(inst.instance_name)):
            continue

        ports: list[InstancePort] = []
        for port in inst.ports.all():
            ports.append(
                InstancePort(
                    port=int(port.port),
                    protocol=int(port.protocol),
                    protocol_name=str(port.protocol_name),
                    name=str(port.name),
                    description=str(port.description),
                    required=port.required,
                    listening=port.listening,
                    verified=port.verified,
                    is_user_defined=port.is_user_defined,
                    is_firewall_target=port.is_firewall_target,
                    range=port.range,
                    network_raw=port.network_raw if isinstance(port.network_raw, dict) else None,
                    core_raw=port.core_raw if isinstance(port.core_raw, dict) else None,
                )
            )

        rows.append(
            InstancePorts(
                instance_id=str(inst.instance_id),
                instance_name=str(inst.instance_name),
                friendly_name=str(inst.friendly_name),
                module=str(inst.module),
                running=bool(inst.running),
                ports=ports,
            )
        )
    return rows


def index(request: HttpRequest) -> HttpResponse:
    filter_form = PortListFilterForm(request.GET or None)
    include_ads = bool(filter_form.data.get("include_ads")) if filter_form.is_bound else False
    active_only = bool(filter_form.data.get("active_only")) if filter_form.is_bound else False
    available_choices = list(provider_choices(only_available=True))
    provider_id = available_choices[0][0] if available_choices else ""
    filter_field = "name"
    filter_query = ""

    if filter_form.is_valid():
        include_ads = bool(filter_form.cleaned_data["include_ads"])
        active_only = bool(filter_form.cleaned_data["active_only"])
        selected = str(filter_form.cleaned_data.get("provider_id") or "")
        filter_field = str(filter_form.cleaned_data.get("filter_field") or "name")
        filter_query = str(filter_form.cleaned_data.get("filter_query") or "").strip()
        if selected:
            provider_id = selected

    provider = None
    if provider_id:
        try:
            provider = get_provider(provider_id, require_available=True)
        except Exception as exc:
            messages.error(request, f"Selected provider is not available: {exc}")

    skip_sync = _truthy(request.GET.get("skip_sync"))
    if skip_sync:
        instances = _load_snapshot_instances(include_ads=include_ads)
    else:
        try:
            collector = AMPPortCollector()
            instances = collector.collect(include_ads=include_ads)
            sync_result = sync_discovered_data(instances)
            if any(
                [
                    sync_result.instances_added,
                    sync_result.instances_removed,
                    sync_result.ports_added,
                    sync_result.ports_removed,
                ]
            ):
                messages.info(
                    request,
                    "Sync update: "
                    f"instances +{sync_result.instances_added}/-{sync_result.instances_removed}, "
                    f"ports +{sync_result.ports_added}/-{sync_result.ports_removed}",
                )
        except Exception as exc:
            msg = str(exc)
            if "Missing AMP credentials" in msg:
                providers_url = reverse("ports-providers")
                messages.warning(
                    request,
                    f"AMP is not configured yet. Open {providers_url} and set AMP URL/username/password.",
                )
            else:
                messages.error(request, f"Failed to collect ports: {exc}")
            instances = []

    rendered_instances: list[dict[str, object]] = []
    instance_ports_map: dict[str, set[tuple[str, int]]] = {}
    for inst in instances:
        rendered_ports: list[dict[str, object]] = []
        for port in inst.ports:
            if filter_query:
                candidate = port.name if filter_field == "name" else port.description
                if filter_query.lower() not in str(candidate or "").lower():
                    continue
            target = FirewallPortTarget(
                instance_name=inst.instance_name,
                port=port.port,
                protocol=port.protocol_name,
                instance_friendly_name=inst.friendly_name,
                description=port.description or port.name,
            )
            if provider is None:
                status_value = FirewallPortStatus.UNKNOWN.value
                status_message = "No configured localhost provider is available."
            else:
                status_result = provider.get_status(target=target)
                status_value = status_result.status.value
                status_message = status_result.message
                if port.listening is False:
                    if status_value == FirewallPortStatus.OPEN.value:
                        status_value = "Open/Service not listening"
                    status_message = f"{status_message} Service is not listening on this port."

            if active_only and status_value != FirewallPortStatus.OPEN.value:
                continue

            rendered_ports.append(
                {
                    "port": port,
                    "status": status_value,
                    "status_message": status_message,
                }
            )

            key = (str(port.protocol_name).lower(), int(port.port))
            instance_key = str(inst.instance_name).strip().lower()
            instance_ports_map.setdefault(instance_key, set()).add(key)
            friendly_key = str(inst.friendly_name).strip().lower()
            if friendly_key:
                instance_ports_map.setdefault(friendly_key, set()).add(key)

        rendered_instances.append({"meta": inst, "ports": rendered_ports})

    orphan_rules: list[dict[str, object]] = []
    is_openwrt_provider = provider is not None and provider.provider_id == "openwrt"
    if is_openwrt_provider and hasattr(provider, "list_managed_rules"):
        try:
            managed_rules = provider.list_managed_rules()
            for rule in managed_rules:
                rule_instance = str(rule.get("instance_name", "") or "").strip().lower()
                rule_proto = str(rule.get("proto", "") or "").lower()
                rule_port = int(rule.get("port") or 0)
                is_orphan = False
                reason = ""
                if not rule_instance:
                    is_orphan = True
                    reason = "No instance name parsed from AMP rule name."
                elif rule_instance not in instance_ports_map:
                    is_orphan = True
                    reason = "Instance from rule name is not in discovered AMP instances."
                elif (rule_proto, rule_port) not in instance_ports_map.get(rule_instance, set()):
                    is_orphan = True
                    reason = "Rule port/protocol is not present on that instance in AMP."
                if is_orphan:
                    orphan_rules.append(
                        {
                            "rule": rule,
                            "reason": reason,
                        }
                    )
        except Exception as exc:
            messages.error(request, f"Failed to inspect managed OpenWrt rules: {exc}")

    context = {
        "filter_form": filter_form,
        "instances": rendered_instances,
        "selected_provider_id": provider_id,
        "selected_filter_field": filter_field,
        "selected_filter_query": filter_query,
        "selected_active_only": active_only,
        "orphan_rules": orphan_rules,
        "is_openwrt_provider": is_openwrt_provider,
    }
    return render(request, "ports/index.html", context)


def sync_progress(request: HttpRequest) -> StreamingHttpResponse:
    include_ads = _truthy(request.GET.get("include_ads"))
    event_queue: queue.Queue[dict[str, object]] = queue.Queue()

    def emit(item: dict[str, object]) -> None:
        event_queue.put(item)

    def worker() -> None:
        try:
            emit({"type": "status", "done": 0, "total": 0, "message": "Connecting to AMP..."})
            collector = AMPPortCollector()
            instances = collector.collect(
                include_ads=include_ads,
                progress_cb=lambda done, total, message: emit(
                    {"type": "progress", "done": done, "total": total, "message": message}
                ),
            )
            emit({"type": "status", "done": len(instances), "total": len(instances), "message": "Syncing snapshot..."})
            sync_result = sync_discovered_data(instances)
            emit(
                {
                    "type": "done",
                    "done": len(instances),
                    "total": len(instances),
                    "message": (
                        "Sync complete. "
                        f"instances +{sync_result.instances_added}/-{sync_result.instances_removed}, "
                        f"ports +{sync_result.ports_added}/-{sync_result.ports_removed}"
                    ),
                }
            )
        except Exception as exc:
            emit({"type": "error", "message": str(exc)})

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    def event_stream():
        while True:
            payload = event_queue.get()
            event_type = str(payload.get("type", "status"))
            data = json.dumps(payload)
            yield f"event: {event_type}\n"
            yield f"data: {data}\n\n"
            if event_type in {"done", "error"}:
                break

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


def apply_port_action(request: HttpRequest) -> HttpResponse:
    wants_json = (
        request.headers.get("x-requested-with") == "XMLHttpRequest"
        or "application/json" in request.headers.get("accept", "").lower()
        or _truthy(request.POST.get("response_json"))
    )

    def _redirect_back() -> HttpResponse:
        url = reverse("ports-index")
        qs = _build_return_query_from_source(request.POST)
        if qs:
            url = f"{url}{qs}"
        return redirect(url)

    if request.method != "POST":
        if wants_json:
            return JsonResponse({"success": False, "message": "POST required."}, status=405)
        return redirect("ports-index")

    form = PortActionForm(request.POST)
    if not form.is_valid():
        msg = f"Invalid action request: {form.errors.as_text()}"
        if wants_json:
            return JsonResponse({"success": False, "message": msg}, status=400)
        messages.error(request, msg)
        return _redirect_back()

    provider_id = str(form.cleaned_data["provider_id"])
    action_value = str(form.cleaned_data["action"])
    action = FirewallAction(action_value)

    target = FirewallPortTarget(
        instance_name=str(form.cleaned_data["instance_name"]),
        port=int(form.cleaned_data["port"]),
        protocol=str(form.cleaned_data["protocol"]),
        instance_friendly_name=str(form.cleaned_data.get("instance_friendly_name", "")),
        description=str(form.cleaned_data["description"]),
    )

    try:
        provider = get_provider(provider_id, require_available=True)
        result = provider.apply(action=action, target=target)
    except Exception as exc:
        msg = f"Provider error: {exc}"
        if wants_json:
            return JsonResponse({"success": False, "message": msg}, status=500)
        messages.error(request, msg)
        return _redirect_back()

    command_text = " ".join(result.command) if result.command else ""
    detail = f"{result.message}"
    if command_text:
        detail = f"{detail} | command: {command_text}"

    if wants_json:
        status_value = FirewallPortStatus.UNKNOWN.value
        status_message = result.message
        if result.success:
            try:
                status_result = provider.get_status(target=target)
                status_value = status_result.status.value
                status_message = status_result.message
            except Exception as exc:
                status_message = f"Action applied, but status refresh failed: {exc}"
            try:
                discovered_port = (
                    DiscoveredPort.objects.select_related("instance")
                    .filter(
                        instance__instance_name=target.instance_name,
                        port=target.port,
                        protocol_name__iexact=target.protocol,
                    )
                    .first()
                )
                if discovered_port is not None and discovered_port.listening is False:
                    if status_value == FirewallPortStatus.OPEN.value:
                        status_value = "Open/Service not listening"
                    if "Service is not listening on this port." not in status_message:
                        status_message = f"{status_message} Service is not listening on this port."
            except Exception:
                pass
        return JsonResponse(
            {
                "success": bool(result.success),
                "message": detail,
                "status": status_value,
                "status_message": status_message,
            }
        )

    if result.success:
        messages.success(request, detail)
    else:
        messages.error(request, detail)

    return _redirect_back()


def apply_bulk_action(request: HttpRequest) -> HttpResponse:
    def _redirect_back(form: BulkPortActionForm | None = None) -> HttpResponse:
        source = request.POST
        if form is not None and form.is_valid():
            source = form.cleaned_data  # type: ignore[assignment]
        url = reverse("ports-index")
        qs = _build_return_query_from_source(source)  # type: ignore[arg-type]
        if qs:
            url = f"{url}{qs}"
        return redirect(url)

    if request.method != "POST":
        return redirect("ports-index")

    form = BulkPortActionForm(request.POST)
    if not form.is_valid():
        messages.error(request, f"Invalid bulk request: {form.errors.as_text()}")
        return _redirect_back()

    provider_id = str(form.cleaned_data["provider_id"])
    action = FirewallAction(str(form.cleaned_data["action"]))
    try:
        targets_payload = json.loads(str(form.cleaned_data["targets_json"]))
        if not isinstance(targets_payload, list):
            raise ValueError("targets_json must be a JSON array")
    except Exception as exc:
        messages.error(request, f"Invalid selected targets payload: {exc}")
        return _redirect_back(form)

    targets: list[FirewallPortTarget] = []
    for item in targets_payload:
        if not isinstance(item, dict):
            continue
        try:
            targets.append(
                FirewallPortTarget(
                    instance_name=str(item.get("instance_name", "")),
                    port=int(item.get("port")),
                    protocol=str(item.get("protocol", "")),
                    instance_friendly_name=str(item.get("instance_friendly_name", "")),
                    description=str(item.get("description", "")),
                )
            )
        except Exception:
            continue

    if not targets:
        messages.error(request, "No valid selected ports to process.")
        return _redirect_back(form)

    try:
        provider = get_provider(provider_id, require_available=True)
    except Exception as exc:
        messages.error(request, f"Provider error: {exc}")
        return _redirect_back(form)

    ok = 0
    failed = 0
    for target in targets:
        result = provider.apply(action=action, target=target)
        if result.success:
            ok += 1
        else:
            failed += 1
            messages.error(
                request,
                f"{target.instance_name} {target.port}/{target.protocol}: {result.message}",
            )

    messages.success(request, f"Bulk {action.value}: success={ok} failed={failed}")
    return _redirect_back(form)


def apply_orphan_action(request: HttpRequest) -> HttpResponse:
    def _redirect_back(form: OrphanRuleActionForm | None = None) -> HttpResponse:
        source = request.POST
        if form is not None and form.is_valid():
            source = form.cleaned_data  # type: ignore[assignment]
        url = reverse("ports-index")
        qs = _build_return_query_from_source(source)  # type: ignore[arg-type]
        if qs:
            url = f"{url}{qs}"
        return redirect(url)

    if request.method != "POST":
        return redirect("ports-index")

    form = OrphanRuleActionForm(request.POST)
    if not form.is_valid():
        messages.error(request, f"Invalid orphan action request: {form.errors.as_text()}")
        return _redirect_back()

    provider_id = str(form.cleaned_data["provider_id"])
    action = str(form.cleaned_data["action"])
    section = str(form.cleaned_data["section"])

    try:
        provider = get_provider(provider_id, require_available=True)
        if provider.provider_id != "openwrt":
            raise RuntimeError("Orphan action is only supported for openwrt provider.")
        if action == "disable":
            provider.disable_rule_by_section(section)  # type: ignore[attr-defined]
            messages.success(request, f"Disabled orphan OpenWrt rule section {section}.")
        elif action == "delete":
            provider.delete_rule_by_section(section)  # type: ignore[attr-defined]
            messages.success(request, f"Deleted orphan OpenWrt rule section {section}.")
        else:
            raise RuntimeError(f"Unsupported orphan action: {action}")
    except Exception as exc:
        messages.error(request, f"Orphan action failed: {exc}")

    return _redirect_back(form)


def apply_orphan_bulk_action(request: HttpRequest) -> HttpResponse:
    def _redirect_back(form: OrphanRuleBulkActionForm | None = None) -> HttpResponse:
        source = request.POST
        if form is not None and form.is_valid():
            source = form.cleaned_data  # type: ignore[assignment]
        url = reverse("ports-index")
        qs = _build_return_query_from_source(source)  # type: ignore[arg-type]
        if qs:
            url = f"{url}{qs}"
        return redirect(url)

    if request.method != "POST":
        return redirect("ports-index")

    form = OrphanRuleBulkActionForm(request.POST)
    if not form.is_valid():
        messages.error(request, f"Invalid orphan bulk request: {form.errors.as_text()}")
        return _redirect_back()

    provider_id = str(form.cleaned_data["provider_id"])
    action = str(form.cleaned_data["action"])
    if action != "delete":
        messages.error(request, "Only bulk delete is supported for orphan rules.")
        return _redirect_back(form)

    try:
        sections_payload = json.loads(str(form.cleaned_data["sections_json"]))
        if not isinstance(sections_payload, list):
            raise ValueError("sections_json must be a JSON array")
    except Exception as exc:
        messages.error(request, f"Invalid selected orphan sections payload: {exc}")
        return _redirect_back(form)

    sections = [str(x).strip() for x in sections_payload if str(x).strip()]
    if not sections:
        messages.error(request, "No valid orphan rule sections selected for bulk delete.")
        return _redirect_back(form)

    try:
        provider = get_provider(provider_id, require_available=True)
        if provider.provider_id != "openwrt":
            raise RuntimeError("Orphan bulk action is only supported for openwrt provider.")
    except Exception as exc:
        messages.error(request, f"Provider error: {exc}")
        return _redirect_back(form)

    ok = 0
    failed = 0
    for section in sections:
        try:
            provider.delete_rule_by_section(section)  # type: ignore[attr-defined]
            ok += 1
        except Exception as exc:
            failed += 1
            messages.error(request, f"Orphan section {section}: delete failed: {exc}")

    messages.success(request, f"Bulk orphan delete: success={ok} failed={failed}")
    return _redirect_back(form)


def provider_config(request: HttpRequest) -> HttpResponse:
    metas = list_provider_meta()
    provider_ids = [m.provider_id for m in metas]
    meta_by_id = {m.provider_id: m for m in metas}

    if request.method == "POST":
        form_action = str(request.POST.get("form_action", "save")).strip().lower()
        amp_obj, _ = AMPConnectionConfig.objects.get_or_create(config_key="default")
        amp_obj.url = (request.POST.get("amp__url") or "").strip()
        amp_obj.username = (request.POST.get("amp__username") or "").strip()
        raw_amp_password = request.POST.get("amp__password")
        if raw_amp_password is not None and raw_amp_password.strip():
            amp_obj.set_password(raw_amp_password.strip())
        amp_obj.save()

        for provider_id in provider_ids:
            meta = meta_by_id[provider_id]
            if meta.local_provider:
                # Local providers are auto-detected and do not need manual config.
                continue
            obj, _ = FirewallProviderConfig.objects.get_or_create(provider_id=provider_id)
            obj.enabled = request.POST.get(f"{provider_id}__enabled") == "on"

            if provider_id == "openwrt":
                obj.openwrt_rpc_url = (request.POST.get("openwrt__rpc_url") or "").strip()
                obj.openwrt_username = (request.POST.get("openwrt__username") or "").strip()
                raw_password = request.POST.get("openwrt__password")
                if raw_password is not None and raw_password.strip():
                    obj.set_openwrt_password(raw_password.strip())
                obj.openwrt_source_zone = (request.POST.get("openwrt__source_zone") or "").strip() or "publicinternal"
                obj.openwrt_forward_source_zone = (
                    request.POST.get("openwrt__forward_source_zone") or ""
                ).strip() or "wan"
                obj.openwrt_forward_dest_zone = (
                    request.POST.get("openwrt__forward_dest_zone") or ""
                ).strip() or "publicinternal"
                obj.openwrt_forward_dest_ip = (request.POST.get("openwrt__forward_dest_ip") or "").strip()
                obj.openwrt_manage_mode = (request.POST.get("openwrt__manage_mode") or "").strip() or "redirect"
                obj.openwrt_aggressive_mode = request.POST.get("openwrt__aggressive_mode") == "on"
                obj.openwrt_name_prefix = (request.POST.get("openwrt__name_prefix") or "").strip() or "arksa-ports-web"
                obj.openwrt_display_prefix = (request.POST.get("openwrt__display_prefix") or "").strip() or "AMP:"

            obj.save()

        if form_action == "test":
            amp_password = ""
            try:
                amp_password = amp_obj.get_password()
            except Exception as exc:
                messages.error(request, f"AMP credential decode failed: {exc}")

            amp_ok, amp_message = test_amp_connection(
                url=amp_obj.url,
                username=amp_obj.username,
                password=amp_password,
            )
            if amp_ok:
                messages.success(request, amp_message)
            else:
                messages.error(request, f"AMP test failed: {amp_message}")

            current_metas = list_provider_meta()
            for meta in current_metas:
                try:
                    provider = get_provider(meta.provider_id)
                except Exception as exc:
                    messages.error(request, f"{meta.display_name}: load failed: {exc}")
                    continue

                if meta.local_provider:
                    supported, support_reason = provider.is_supported()
                    in_use = False
                    in_use_reason = support_reason
                    if supported:
                        in_use, in_use_reason = provider.is_in_use()
                    if supported and in_use:
                        messages.success(request, f"{meta.display_name}: OK ({in_use_reason})")
                    else:
                        messages.error(request, f"{meta.display_name}: Not available ({in_use_reason})")
                    continue

                if not meta.enabled:
                    messages.info(request, f"{meta.display_name}: Skipped (provider disabled).")
                    continue
                if not provider.has_required_config():
                    messages.error(request, f"{meta.display_name}: Missing required configuration fields.")
                    continue
                supported, support_reason = provider.is_supported()
                if supported:
                    messages.success(request, f"{meta.display_name}: OK ({support_reason})")
                else:
                    messages.error(request, f"{meta.display_name}: Failed ({support_reason})")
        else:
            messages.success(request, "Provider configuration saved.")
        return redirect("ports-providers")

    defaults = getattr(settings, "FIREWALL_PROVIDER_DEFAULT_CONFIGS", {})
    openwrt_default = defaults.get("openwrt", {}) if isinstance(defaults, dict) else {}
    if not isinstance(openwrt_default, dict):
        openwrt_default = {}

    configs = {c.provider_id: c for c in FirewallProviderConfig.objects.all()}
    amp_cfg = AMPConnectionConfig.objects.filter(config_key="default").first()
    rows: list[dict[str, object]] = []
    for meta in metas:
        cfg = configs.get(meta.provider_id)
        openwrt_defaults_auth = openwrt_default.get("auth", {})
        if not isinstance(openwrt_defaults_auth, dict):
            openwrt_defaults_auth = {}
        rows.append(
            {
                "meta": meta,
                "enabled": True if meta.local_provider else (bool(cfg.enabled) if cfg else False),
                "editable": not meta.local_provider,
                "config_fields": {
                    "rpc_url": (cfg.openwrt_rpc_url if cfg else str(openwrt_default.get("rpc_url", ""))).strip(),
                    "username": (
                        cfg.openwrt_username if cfg else str(openwrt_defaults_auth.get("username", ""))
                    ).strip(),
                    "password_is_set": bool((cfg.openwrt_password_encrypted if cfg else "").strip()),
                    "source_zone": (
                        cfg.openwrt_source_zone if cfg else str(openwrt_default.get("source_zone", "publicinternal"))
                    ).strip()
                    or "publicinternal",
                    "forward_source_zone": (
                        cfg.openwrt_forward_source_zone
                        if cfg
                        else str(openwrt_default.get("forward_source_zone", "wan"))
                    ).strip()
                    or "wan",
                    "forward_dest_zone": (
                        cfg.openwrt_forward_dest_zone
                        if cfg
                        else str(openwrt_default.get("forward_dest_zone", "publicinternal"))
                    ).strip()
                    or "publicinternal",
                    "forward_dest_ip": (
                        cfg.openwrt_forward_dest_ip if cfg else str(openwrt_default.get("forward_dest_ip", ""))
                    ).strip(),
                    "manage_mode": (
                        cfg.openwrt_manage_mode if cfg else str(openwrt_default.get("manage_mode", "redirect"))
                    ).strip()
                    or "redirect",
                    "aggressive_mode": (
                        bool(cfg.openwrt_aggressive_mode)
                        if cfg
                        else str(openwrt_default.get("aggressive_mode", "1")).strip().lower() in {"1", "true", "yes", "on"}
                    ),
                    "name_prefix": (
                        cfg.openwrt_name_prefix if cfg else str(openwrt_default.get("name_prefix", "arksa-ports-web"))
                    ).strip()
                    or "arksa-ports-web",
                    "display_prefix": (
                        cfg.openwrt_display_prefix if cfg else str(openwrt_default.get("display_prefix", "AMP:"))
                    ).strip()
                    or "AMP:",
                },
            }
        )

    amp_fields = {
        "url": str(amp_cfg.url if amp_cfg else "").strip(),
        "username": str(amp_cfg.username if amp_cfg else "").strip(),
        "password_is_set": bool(str(amp_cfg.password_encrypted if amp_cfg else "").strip()),
    }
    return render(request, "ports/providers.html", {"rows": rows, "amp_fields": amp_fields})
