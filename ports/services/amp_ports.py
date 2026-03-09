from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable

from ampapi import AMPControllerInstance, APIParams, Bridge
from ampapi.modules import ActionResultError
from django.db.utils import OperationalError, ProgrammingError

from ports.models import AMPConnectionConfig


@dataclass(frozen=True)
class InstancePort:
    port: int
    protocol: int
    protocol_name: str
    name: str
    description: str
    required: bool | None
    listening: bool | None
    verified: bool | None
    is_user_defined: bool | None
    is_firewall_target: bool | None
    range: int | None
    network_raw: dict[str, Any] | None
    core_raw: dict[str, Any] | None


@dataclass(frozen=True)
class InstancePorts:
    instance_id: str
    instance_name: str
    friendly_name: str
    module: str
    running: bool
    ports: list[InstancePort]


class SafeAMPControllerInstance(AMPControllerInstance):
    # Avoid ampapi __del__ teardown warnings; we close explicitly.
    def __del__(self) -> None:
        return


class AMPPortCollector:
    def __init__(self) -> None:
        self._amp_url, self._amp_user, self._amp_pass = self._load_credentials()

    def _load_credentials(self) -> tuple[str, str, str]:
        # Source: DB configuration managed in /providers UI.
        try:
            cfg_row = AMPConnectionConfig.objects.filter(config_key="default").first()
            if cfg_row is not None:
                amp_url = str(cfg_row.url or "").strip()
                amp_user = str(cfg_row.username or "").strip()
                amp_pass = str(cfg_row.get_password() or "").strip()
                if amp_url and amp_user and amp_pass:
                    return amp_url, amp_user, amp_pass
        except (OperationalError, ProgrammingError):
            # Migrations may not have run yet.
            pass
        except Exception:
            pass

        raise RuntimeError("Missing AMP credentials. Configure AMP in /providers.")

    @staticmethod
    def _is_ads(module: str, instance_name: str) -> bool:
        return module == "ADS" or instance_name.startswith("ADS")

    @staticmethod
    def _protocol_name(protocol: int) -> str:
        if protocol in (0, 6):
            return "tcp"
        if protocol in (1, 17):
            return "udp"
        return str(protocol)

    async def _connect(self) -> SafeAMPControllerInstance:
        params = APIParams(url=self._amp_url, user=self._amp_user, password=self._amp_pass)
        Bridge(api_params=params)
        ads = SafeAMPControllerInstance()
        login_result = await ads.login(amp_user=self._amp_user, amp_password=self._amp_pass)
        if isinstance(login_result, ActionResultError):
            raise RuntimeError(f"AMP login failed: {login_result}")
        return ads

    async def _network_ports(self, ads: SafeAMPControllerInstance, instance_name: str) -> list[dict[str, Any]]:
        result = await ads.get_instance_network_info(instance_name=instance_name, format_data=False)
        if isinstance(result, ActionResultError) or not isinstance(result, list):
            return []
        return [dict(x) for x in result if isinstance(x, dict)]

    async def _core_ports(self, ads: SafeAMPControllerInstance, instance_id: str, running: bool) -> list[dict[str, Any]]:
        if not running:
            return []
        instance_obj = await ads.get_instance(instance_id=instance_id, format_data=True)
        if isinstance(instance_obj, ActionResultError):
            return []
        result = await instance_obj.get_port_summaries(format_data=False)
        if isinstance(result, ActionResultError) or not isinstance(result, list):
            return []
        return [dict(x) for x in result if isinstance(x, dict)]

    def _merge_ports(self, network_ports: list[dict[str, Any]], core_ports: list[dict[str, Any]]) -> list[InstancePort]:
        merged: dict[tuple[int, int], dict[str, Any]] = {}

        for raw in network_ports:
            port = raw.get("port_number")
            protocol = raw.get("protocol")
            if not isinstance(port, int) or not isinstance(protocol, int):
                continue
            merged[(port, protocol)] = {
                "port": port,
                "protocol": protocol,
                "description": str(raw.get("description", "") or ""),
                "name": "",
                "required": None,
                "listening": None,
                "verified": raw.get("verified") if isinstance(raw.get("verified"), bool) else None,
                "is_user_defined": raw.get("is_user_defined")
                if isinstance(raw.get("is_user_defined"), bool)
                else None,
                "is_firewall_target": raw.get("is_firewall_target")
                if isinstance(raw.get("is_firewall_target"), bool)
                else None,
                "range": raw.get("range") if isinstance(raw.get("range"), int) else None,
                "network_raw": raw,
                "core_raw": None,
            }

        for raw in core_ports:
            port = raw.get("port")
            protocol = raw.get("protocol")
            if not isinstance(port, int) or not isinstance(protocol, int):
                continue
            key = (port, protocol)
            entry = merged.get(
                key,
                {
                    "port": port,
                    "protocol": protocol,
                    "description": "",
                    "name": "",
                    "required": None,
                    "listening": None,
                    "verified": None,
                    "is_user_defined": None,
                    "is_firewall_target": None,
                    "range": None,
                    "network_raw": None,
                    "core_raw": None,
                },
            )
            entry["name"] = str(raw.get("name", "") or "")
            entry["required"] = raw.get("required") if isinstance(raw.get("required"), bool) else None
            entry["listening"] = raw.get("listening") if isinstance(raw.get("listening"), bool) else None
            entry["core_raw"] = raw
            merged[key] = entry

        rows: list[InstancePort] = []
        for key in sorted(merged.keys()):
            row = merged[key]
            rows.append(
                InstancePort(
                    port=row["port"],
                    protocol=row["protocol"],
                    protocol_name=self._protocol_name(row["protocol"]),
                    name=row["name"],
                    description=row["description"],
                    required=row["required"],
                    listening=row["listening"],
                    verified=row["verified"],
                    is_user_defined=row["is_user_defined"],
                    is_firewall_target=row["is_firewall_target"],
                    range=row["range"],
                    network_raw=row["network_raw"],
                    core_raw=row["core_raw"],
                )
            )
        return rows

    async def collect_async(
        self,
        include_ads: bool = False,
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> list[InstancePorts]:
        ads = await self._connect()
        try:
            instances = await ads.get_instances(format_data=True)
            if isinstance(instances, ActionResultError):
                raise RuntimeError(f"Failed to list instances: {instances}")

            ordered_instances = sorted(instances, key=lambda x: str(getattr(x, "instance_name", "")).lower())
            filtered_instances = [
                inst
                for inst in ordered_instances
                if include_ads
                or not self._is_ads(
                    module=str(getattr(inst, "module", "")),
                    instance_name=str(getattr(inst, "instance_name", "")),
                )
            ]
            total_instances = len(filtered_instances)
            if progress_cb is not None:
                progress_cb(0, total_instances, "Connected to AMP")

            rows: list[InstancePorts] = []
            done_instances = 0
            for inst in filtered_instances:
                instance_name = str(getattr(inst, "instance_name", ""))
                module = str(getattr(inst, "module", ""))

                instance_id = str(getattr(inst, "instance_id", ""))
                if not instance_id or not instance_name:
                    continue

                running = bool(getattr(inst, "running", False))
                network_raw = await self._network_ports(ads=ads, instance_name=instance_name)
                core_raw = await self._core_ports(ads=ads, instance_id=instance_id, running=running)
                merged = self._merge_ports(network_ports=network_raw, core_ports=core_raw)

                rows.append(
                    InstancePorts(
                        instance_id=instance_id,
                        instance_name=instance_name,
                        friendly_name=str(getattr(inst, "friendly_name", "")),
                        module=module,
                        running=running,
                        ports=merged,
                    )
                )
                done_instances += 1
                if progress_cb is not None:
                    progress_cb(done_instances, total_instances, f"Loaded {instance_name}")
            return rows
        finally:
            await ads.__adel__()

    def collect(
        self,
        include_ads: bool = False,
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> list[InstancePorts]:
        return asyncio.run(self.collect_async(include_ads=include_ads, progress_cb=progress_cb))


async def _test_amp_connection_async(url: str, username: str, password: str) -> int:
    params = APIParams(url=url, user=username, password=password)
    Bridge(api_params=params)
    ads = SafeAMPControllerInstance()
    try:
        login_result = await ads.login(amp_user=username, amp_password=password)
        if isinstance(login_result, ActionResultError):
            raise RuntimeError(f"AMP login failed: {login_result}")
        instances = await ads.get_instances(format_data=True)
        if isinstance(instances, ActionResultError):
            raise RuntimeError(f"AMP instance query failed: {instances}")
        if isinstance(instances, (list, set, tuple)):
            return len(instances)
        if isinstance(instances, dict):
            # Be tolerant of wrapped payloads if AMP/ampapi changes shape.
            for key in ("instances", "available_instances", "result"):
                value = instances.get(key)
                if isinstance(value, (list, set, tuple)):
                    return len(value)
            raise RuntimeError("Unexpected AMP response: instances list missing")
        if hasattr(instances, "__iter__") and not isinstance(instances, (str, bytes)):
            return sum(1 for _ in instances)
        raise RuntimeError("Unexpected AMP response: instances list missing")
    finally:
        await ads.__adel__()


def test_amp_connection(url: str, username: str, password: str) -> tuple[bool, str]:
    url_value = str(url or "").strip()
    user_value = str(username or "").strip()
    pass_value = str(password or "").strip()
    if not url_value or not user_value or not pass_value:
        return False, "AMP URL/username/password are required."
    try:
        count = asyncio.run(_test_amp_connection_async(url_value, user_value, pass_value))
        return True, f"AMP connection OK (instances visible: {count})."
    except Exception as exc:
        return False, str(exc)
