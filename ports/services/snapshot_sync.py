from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction

from ports.models import DiscoveredInstance, DiscoveredPort

from .amp_ports import InstancePorts


@dataclass(frozen=True)
class SyncResult:
    instances_added: int
    instances_updated: int
    instances_removed: int
    ports_added: int
    ports_updated: int
    ports_removed: int


def sync_discovered_data(instances: list[InstancePorts]) -> SyncResult:
    instances_added = 0
    instances_updated = 0
    instances_removed = 0
    ports_added = 0
    ports_updated = 0
    ports_removed = 0

    seen_instance_ids = {i.instance_id for i in instances}

    with transaction.atomic():
        existing_by_id = {x.instance_id: x for x in DiscoveredInstance.objects.all()}

        stale_instances_qs = DiscoveredInstance.objects.exclude(instance_id__in=seen_instance_ids)
        instances_removed = stale_instances_qs.count()
        stale_instances_qs.delete()

        for item in instances:
            db_instance = existing_by_id.get(item.instance_id)
            if db_instance is None:
                db_instance = DiscoveredInstance.objects.create(
                    instance_id=item.instance_id,
                    instance_name=item.instance_name,
                    friendly_name=item.friendly_name,
                    module=item.module,
                    running=item.running,
                )
                instances_added += 1
            else:
                changed = False
                if db_instance.instance_name != item.instance_name:
                    db_instance.instance_name = item.instance_name
                    changed = True
                if db_instance.friendly_name != item.friendly_name:
                    db_instance.friendly_name = item.friendly_name
                    changed = True
                if db_instance.module != item.module:
                    db_instance.module = item.module
                    changed = True
                if db_instance.running != item.running:
                    db_instance.running = item.running
                    changed = True
                if changed:
                    db_instance.save(update_fields=["instance_name", "friendly_name", "module", "running", "last_seen_at"])
                    instances_updated += 1
                else:
                    db_instance.save(update_fields=["last_seen_at"])

            existing_ports = {(p.port, p.protocol): p for p in db_instance.ports.all()}
            incoming_keys = {(p.port, p.protocol) for p in item.ports}

            # Filter by tuple precisely in Python since sqlite tuple filtering is clunky.
            stale_ids = [p.id for p in db_instance.ports.all() if (p.port, p.protocol) not in incoming_keys]
            if stale_ids:
                ports_removed += len(stale_ids)
                DiscoveredPort.objects.filter(id__in=stale_ids).delete()

            for port in item.ports:
                key = (port.port, port.protocol)
                db_port = existing_ports.get(key)
                if db_port is None:
                    DiscoveredPort.objects.create(
                        instance=db_instance,
                        port=port.port,
                        protocol=port.protocol,
                        protocol_name=port.protocol_name,
                        name=port.name,
                        description=port.description,
                        required=port.required,
                        listening=port.listening,
                        verified=port.verified,
                        is_user_defined=port.is_user_defined,
                        is_firewall_target=port.is_firewall_target,
                        range=port.range,
                        network_raw=port.network_raw,
                        core_raw=port.core_raw,
                    )
                    ports_added += 1
                    continue

                changed = False
                field_values = {
                    "protocol_name": port.protocol_name,
                    "name": port.name,
                    "description": port.description,
                    "required": port.required,
                    "listening": port.listening,
                    "verified": port.verified,
                    "is_user_defined": port.is_user_defined,
                    "is_firewall_target": port.is_firewall_target,
                    "range": port.range,
                    "network_raw": port.network_raw,
                    "core_raw": port.core_raw,
                }
                for field, value in field_values.items():
                    if getattr(db_port, field) != value:
                        setattr(db_port, field, value)
                        changed = True

                if changed:
                    db_port.save(update_fields=[*field_values.keys(), "last_seen_at"])
                    ports_updated += 1
                else:
                    db_port.save(update_fields=["last_seen_at"])

    return SyncResult(
        instances_added=instances_added,
        instances_updated=instances_updated,
        instances_removed=instances_removed,
        ports_added=ports_added,
        ports_updated=ports_updated,
        ports_removed=ports_removed,
    )
