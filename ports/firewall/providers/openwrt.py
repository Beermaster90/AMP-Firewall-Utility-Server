from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

from django.conf import settings

from ..base import (
    FirewallAction,
    FirewallActionResult,
    FirewallPortStatus,
    FirewallPortTarget,
    FirewallProvider,
    FirewallStatusResult,
)


class OpenWrtFirewallProvider(FirewallProvider):
    provider_id = "openwrt"
    display_name = "OpenWrt (ubus RPC)"
    local_provider = False
    required_config_fields = ("rpc_url", "auth")

    def has_required_config(self) -> bool:
        if not super().has_required_config():
            return False
        auth = self._auth()
        return bool(auth.get("username")) and bool(auth.get("password"))

    def is_supported(self) -> tuple[bool, str]:
        try:
            session = self._login()
            _ = self._rpc_call(session=session, object_name="uci", method="get", params={"config": "firewall"})
            return True, "OpenWrt RPC reachable and firewall UCI access works."
        except Exception as exc:
            return False, f"OpenWrt RPC unavailable: {exc}"

    def is_in_use(self) -> tuple[bool, str]:
        ok, msg = self.is_supported()
        if ok:
            return True, "OpenWrt firewall management is active via RPC."
        return False, msg

    def get_status(self, target: FirewallPortTarget) -> FirewallStatusResult:
        try:
            values = self._firewall_values()
        except Exception as exc:
            return FirewallStatusResult(
                provider_id=self.provider_id,
                target=target,
                status=FirewallPortStatus.UNKNOWN,
                message=f"OpenWrt RPC read failed: {exc}",
            )

        sections = self._matching_sections(values=values, target=target)
        exact_sections = [item for item in sections if bool(item["exact_port"])]
        range_sections = [item for item in sections if not bool(item["exact_port"])]

        if not exact_sections:
            if range_sections:
                return FirewallStatusResult(
                    provider_id=self.provider_id,
                    target=target,
                    status=FirewallPortStatus.CLOSED,
                    message="Port only appears inside range-based rule(s); treated as not detected.",
                )
            return FirewallStatusResult(
                provider_id=self.provider_id,
                target=target,
                status=FirewallPortStatus.CLOSED,
                message="No matching OpenWrt firewall allow rule.",
            )

        for item in exact_sections:
            rule = item["rule"]
            enabled = str(rule.get("enabled", "1")) != "0"
            if enabled and self._section_allows(rule):
                return FirewallStatusResult(
                    provider_id=self.provider_id,
                    target=target,
                    status=FirewallPortStatus.OPEN,
                    message="Matching enabled OpenWrt allow/forward rule found.",
                )

        if any(str(item["rule"].get("enabled", "1")) == "0" for item in exact_sections):
            return FirewallStatusResult(
                provider_id=self.provider_id,
                target=target,
                status=FirewallPortStatus.DISABLED,
                message="Matching OpenWrt rule exists but is disabled.",
            )

        return FirewallStatusResult(
            provider_id=self.provider_id,
            target=target,
            status=FirewallPortStatus.CLOSED,
            message="Matching rule exists but is not ACCEPT/DNAT.",
        )

    def apply(self, action: FirewallAction, target: FirewallPortTarget) -> FirewallActionResult:
        if not settings.FIREWALL_EXECUTE:
            return FirewallActionResult(
                success=True,
                provider_id=self.provider_id,
                action=action,
                target=target,
                message="Dry run only. Set FIREWALL_EXECUTE=1 to execute provider changes.",
                command=["ubus", "uci", action.value, self._rule_name(target)],
            )

        try:
            session = self._login()
            values = self._firewall_values(session=session)
            matches = self._matching_sections(values=values, target=target)
            exact_matches = [m for m in matches if bool(m["exact_port"])]
            managed_exact = [m for m in exact_matches if bool(m["managed"])]
            range_matches = [m for m in matches if not bool(m["exact_port"])]

            if action is FirewallAction.ENABLE:
                if managed_exact:
                    already_enabled = any(
                        str(item["rule"].get("enabled", "1")) != "0" and self._section_allows(item["rule"])
                        for item in managed_exact
                    )
                    if already_enabled:
                        msg = "Managed OpenWrt rule already enabled; no change needed."
                    else:
                        for item in managed_exact:
                            self._uci_set(
                                session=session,
                                section=str(item["section"]),
                                values={"enabled": "1"},
                            )
                        self._uci_apply(session=session)
                        msg = f"Enabled {len(managed_exact)} managed OpenWrt rule(s)."
                else:
                    section = self._uci_add_rule(session=session, type_=self._manage_mode())
                    self._uci_set(
                        session=session,
                        section=section,
                        values=self._create_values(target=target),
                    )
                    self._uci_apply(session=session)
                    if range_matches and self._aggressive_mode():
                        msg = (
                            f"Created and enabled dedicated OpenWrt rule section '{section}'. "
                            "Range-based rules were ignored for per-port management."
                        )
                    elif range_matches:
                        msg = (
                            f"Created and enabled dedicated OpenWrt rule section '{section}'. "
                            "Range-based rules are not used for detection."
                        )
                    else:
                        msg = f"Created and enabled OpenWrt rule section '{section}'."

            else:
                if not managed_exact:
                    msg = "No matching OpenWrt rule to disable; already closed."
                else:
                    for item in managed_exact:
                        self._uci_set(
                            session=session,
                            section=str(item["section"]),
                            values={"enabled": "0"},
                        )
                    self._uci_apply(session=session)
                    msg = f"Disabled {len(managed_exact)} managed OpenWrt rule(s)."

            return FirewallActionResult(
                success=True,
                provider_id=self.provider_id,
                action=action,
                target=target,
                message=msg,
                command=["ubus", "uci", action.value, self._rule_name(target)],
            )
        except Exception as exc:
            return FirewallActionResult(
                success=False,
                provider_id=self.provider_id,
                action=action,
                target=target,
                message=f"OpenWrt provider error: {exc}",
                command=["ubus", "uci", action.value, self._rule_name(target)],
            )

    def _rpc_url(self) -> str:
        return str(self.config.get("rpc_url", "")).strip()

    def _auth(self) -> dict[str, str]:
        raw = self.config.get("auth", {})
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    raw = parsed
            except json.JSONDecodeError:
                raw = {}
        if not isinstance(raw, dict):
            raw = {}
        return {
            "username": str(raw.get("username", "")).strip(),
            "password": str(raw.get("password", "")).strip(),
        }

    def _source_zone(self) -> str:
        return str(self.config.get("source_zone", "publicinternal")).strip() or "publicinternal"

    def _forward_source_zone(self) -> str:
        return str(self.config.get("forward_source_zone", "wan")).strip() or "wan"

    def _forward_dest_zone(self) -> str:
        return str(self.config.get("forward_dest_zone", "publicinternal")).strip() or "publicinternal"

    def _forward_dest_ip(self) -> str:
        return str(self.config.get("forward_dest_ip", "")).strip()

    def _manage_mode(self) -> str:
        mode = str(self.config.get("manage_mode", "redirect")).strip().lower()
        return "rule" if mode == "rule" else "redirect"

    def _aggressive_mode(self) -> bool:
        value = str(self.config.get("aggressive_mode", "1")).strip().lower()
        return value in {"1", "true", "yes", "on"}

    def _name_prefix(self) -> str:
        return str(self.config.get("name_prefix", "arksa-ports-web")).strip() or "arksa-ports-web"

    def _display_prefix(self) -> str:
        return str(self.config.get("display_prefix", "AMP:")).strip() or "AMP:"

    def _rule_name(self, target: FirewallPortTarget) -> str:
        proto = self._proto(target.protocol).upper()
        desc = " ".join(str(target.description or "").split()).strip()
        if not desc:
            desc = f"{proto} {target.port}"
        instance = " ".join(str(target.instance_friendly_name or "").split()).strip()
        if not instance:
            instance = " ".join(str(target.instance_name or "").split()).strip()
        if not instance:
            instance = "UnknownInstance"
        return f"{self._display_prefix()} {instance} {desc} ({proto}/{target.port})"

    def _legacy_rule_name(self, target: FirewallPortTarget) -> str:
        proto = self._proto(target.protocol)
        return f"{self._name_prefix()}-{proto}-{target.port}"

    def list_managed_rules(self) -> list[dict[str, Any]]:
        values = self._firewall_values()
        rows: list[dict[str, Any]] = []
        for section, rule in values.items():
            section_type = str(rule.get(".type", ""))
            if section_type not in {"rule", "redirect"}:
                continue
            name = str(rule.get("name", ""))
            if not name.startswith(self._display_prefix()):
                continue

            proto_value = rule.get("proto")
            proto = self._normalize_proto_for_display(proto_value)
            port_spec = rule.get("src_dport") if section_type == "redirect" else rule.get("dest_port")
            port = self._first_port_from_spec(port_spec)
            parsed_instance, parsed_desc, parsed_proto, parsed_port = self._parse_amp_name(name)
            if not proto and parsed_proto:
                proto = parsed_proto
            if port is None and parsed_port is not None:
                port = parsed_port

            rows.append(
                {
                    "section": section,
                    "name": name,
                    "enabled": str(rule.get("enabled", "1")) != "0",
                    "section_type": section_type,
                    "proto": proto,
                    "port": port,
                    "instance_name": parsed_instance or "",
                    "description": parsed_desc or "",
                    "raw": rule,
                }
            )
        rows.sort(key=lambda x: (str(x["instance_name"]).lower(), str(x["proto"]), int(x["port"] or 0), str(x["section"])))
        return rows

    def disable_rule_by_section(self, section: str) -> None:
        session = self._login()
        self._uci_set(session=session, section=section, values={"enabled": "0"})
        self._uci_apply(session=session)

    def delete_rule_by_section(self, section: str) -> None:
        session = self._login()
        self._uci_delete(session=session, section=section)
        self._uci_apply(session=session)

    @staticmethod
    def _proto(proto: str) -> str:
        p = proto.strip().lower()
        if p in {"0", "tcp"}:
            return "tcp"
        if p in {"1", "udp"}:
            return "udp"
        return p

    def _normalize_proto_for_display(self, proto_value: Any) -> str:
        if isinstance(proto_value, list):
            if not proto_value:
                return ""
            return self._proto(str(proto_value[0]))
        text = str(proto_value or "").strip().lower()
        if not text:
            return ""
        if " " in text:
            return self._proto(text.split()[0])
        return self._proto(text)

    @staticmethod
    def _first_port_from_spec(port_spec: Any) -> int | None:
        text = str(port_spec or "").strip()
        if not text:
            return None
        first = text.split()[0]
        if "-" in first:
            first = first.split("-", 1)[0]
        try:
            return int(first)
        except ValueError:
            return None

    @staticmethod
    def _parse_amp_name(name: str) -> tuple[str | None, str | None, str | None, int | None]:
        # AMP: Instance Description (PROTO/1234)
        m = re.match(r"^AMP:\s*(.+?)\s+\((TCP|UDP)/(\d+)\)\s*$", name, flags=re.IGNORECASE)
        if not m:
            return None, None, None, None
        head = m.group(1).strip()
        proto = m.group(2).lower()
        port = int(m.group(3))
        tokens = head.split()
        if len(tokens) <= 1:
            return head, "", proto, port
        # Heuristic split: last 1-3 tokens are likely description; we keep instance as full head if unsure.
        # Prefer "Game Port", "RCON Port", "HTTP Server Port", "SFTP Port".
        known_suffixes = [
            "game port",
            "rcon port",
            "http server port",
            "sftp port",
            "steam query port",
        ]
        lower_head = head.lower()
        for suffix in known_suffixes:
            if lower_head.endswith(" " + suffix):
                instance = head[: -len(suffix)].strip()
                return instance, suffix.title(), proto, port
        return head, "", proto, port

    def _login(self) -> str:
        auth = self._auth()
        response = self._rpc_call(
            session="00000000000000000000000000000000",
            object_name="session",
            method="login",
            params={"username": auth["username"], "password": auth["password"]},
        )
        token = str(response.get("ubus_rpc_session", "")).strip()
        if not token:
            raise RuntimeError("No ubus_rpc_session in login response")
        return token

    def _rpc_call(self, session: str, object_name: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [session, object_name, method, params],
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self._rpc_url(),
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            payload = json.loads(resp.read().decode("utf-8"))

        if "error" in payload:
            raise RuntimeError(payload["error"])

        result = payload.get("result", [])
        if not isinstance(result, list) or not result:
            raise RuntimeError(f"Unexpected RPC response: {payload}")
        if result[0] != 0:
            raise RuntimeError(f"RPC non-zero result: {payload}")
        return result[1] if len(result) > 1 and isinstance(result[1], dict) else {}

    def _firewall_values(self, session: str | None = None) -> dict[str, dict[str, Any]]:
        active_session = session or self._login()
        response = self._rpc_call(
            session=active_session,
            object_name="uci",
            method="get",
            params={"config": "firewall"},
        )
        values = response.get("values", {})
        if not isinstance(values, dict):
            return {}
        return {str(k): v for k, v in values.items() if isinstance(v, dict)}

    def _matching_sections(
        self,
        values: dict[str, dict[str, Any]],
        target: FirewallPortTarget,
    ) -> list[dict[str, Any]]:
        name = self._rule_name(target)
        legacy_name = self._legacy_rule_name(target)
        proto = self._proto(target.protocol)
        port_text = str(target.port)
        src_zone = self._source_zone()
        fw_src = self._forward_source_zone()
        fw_dest = self._forward_dest_zone()
        fw_dest_ip = self._forward_dest_ip()
        matches: list[dict[str, Any]] = []

        for section, rule in values.items():
            section_type = str(rule.get(".type", ""))
            if section_type not in {"rule", "redirect"}:
                continue
            rule_name = str(rule.get("name", ""))
            managed = rule_name in {name, legacy_name}
            if managed:
                # Managed naming is not sufficient on its own: rule must still match port/protocol.
                rule_proto = rule.get("proto")
                if not self._proto_matches(rule_proto, proto):
                    continue
                managed_port_spec = (
                    rule.get("src_dport")
                    if section_type == "redirect"
                    else rule.get("dest_port")
                )
                if not self._port_spec_matches(managed_port_spec, target.port):
                    continue
                matches.append(
                    {
                        "section": section,
                        "rule": rule,
                        "managed": True,
                        "exact_port": self._is_exact_port_spec(managed_port_spec, target.port),
                    }
                )
                continue

            rule_proto = rule.get("proto")
            proto_ok = self._proto_matches(rule_proto, proto)
            if not proto_ok:
                continue

            if section_type == "rule":
                if (
                    str(rule.get("src", "")) == src_zone
                    and self._port_spec_matches(rule.get("dest_port"), target.port)
                ):
                    matches.append(
                        {
                            "section": section,
                            "rule": rule,
                            "managed": False,
                            "exact_port": self._is_exact_port_spec(rule.get("dest_port"), target.port),
                        }
                    )
                continue

            # redirect (DNAT/port-forward)
            if str(rule.get("src", "")) != fw_src:
                continue
            if fw_dest and str(rule.get("dest", "")) not in {"", fw_dest}:
                continue
            if fw_dest_ip and str(rule.get("dest_ip", "")) not in {"", fw_dest_ip}:
                continue
            port_spec = rule.get("src_dport") or rule.get("dest_port")
            if self._port_spec_matches(port_spec, target.port):
                matches.append(
                    {
                        "section": section,
                        "rule": rule,
                        "managed": False,
                        "exact_port": self._is_exact_port_spec(port_spec, target.port),
                    }
                )

        return matches

    def _section_allows(self, rule: dict[str, Any]) -> bool:
        section_type = str(rule.get(".type", ""))
        target_action = str(rule.get("target", "")).upper()
        if section_type == "rule":
            return target_action == "ACCEPT"
        if section_type == "redirect":
            return target_action in {"DNAT", "ACCEPT", ""}
        return False

    def _enable_values_for_section(self, rule: dict[str, Any], target: FirewallPortTarget) -> dict[str, str]:
        section_type = str(rule.get(".type", ""))
        values: dict[str, str] = {"enabled": "1"}
        if section_type == "redirect":
            values.update(
                {
                    "target": "DNAT",
                    "src": str(rule.get("src", "") or self._forward_source_zone()),
                    "dest": str(rule.get("dest", "") or self._forward_dest_zone()),
                    "dest_ip": str(rule.get("dest_ip", "") or self._forward_dest_ip()),
                    "proto": self._proto(target.protocol),
                    "src_dport": str(target.port),
                    "dest_port": str(target.port),
                }
            )
        else:
            values.update(
                {
                    "target": "ACCEPT",
                    "src": str(rule.get("src", "") or self._source_zone()),
                    "proto": self._proto(target.protocol),
                    "dest_port": str(target.port),
                }
            )
        return values

    def _create_values(self, target: FirewallPortTarget) -> dict[str, str]:
        base_name = self._rule_name(target)
        if self._manage_mode() == "redirect":
            return {
                "name": base_name,
                "src": self._forward_source_zone(),
                "dest": self._forward_dest_zone(),
                "dest_ip": self._forward_dest_ip(),
                "proto": self._proto(target.protocol),
                "src_dport": str(target.port),
                "dest_port": str(target.port),
                "target": "DNAT",
                "enabled": "1",
            }
        return {
            "name": base_name,
            "src": self._source_zone(),
            "proto": self._proto(target.protocol),
            "dest_port": str(target.port),
            "target": "ACCEPT",
            "enabled": "1",
        }

    @staticmethod
    def _proto_matches(rule_proto: Any, wanted_proto: str) -> bool:
        wanted = wanted_proto.lower().strip()
        if isinstance(rule_proto, list):
            values = {str(x).lower().strip() for x in rule_proto}
            return not values or wanted in values
        text = str(rule_proto or "").lower().strip()
        if not text:
            return True
        if " " in text:
            return wanted in {x.strip() for x in text.split()}
        return text == wanted

    @staticmethod
    def _parse_port_spec(port_spec: Any) -> list[tuple[int, int]]:
        text = str(port_spec or "").strip()
        if not text:
            return []
        ranges: list[tuple[int, int]] = []
        for chunk in text.split():
            part = chunk.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    start = int(a)
                    end = int(b)
                except ValueError:
                    continue
                if start > end:
                    start, end = end, start
                ranges.append((start, end))
                continue
            try:
                p = int(part)
            except ValueError:
                continue
            ranges.append((p, p))
        return ranges

    @classmethod
    def _port_spec_matches(cls, port_spec: Any, port: int) -> bool:
        for start, end in cls._parse_port_spec(port_spec):
            if start <= port <= end:
                return True
        return False

    @classmethod
    def _is_exact_port_spec(cls, port_spec: Any, port: int) -> bool:
        ranges = cls._parse_port_spec(port_spec)
        return len(ranges) == 1 and ranges[0] == (port, port)

    def _uci_add_rule(self, session: str, type_: str) -> str:
        response = self._rpc_call(
            session=session,
            object_name="uci",
            method="add",
            params={"config": "firewall", "type": type_},
        )
        section = str(response.get("section", "")).strip()
        if not section:
            raise RuntimeError("uci add did not return section id")
        return section

    def _uci_set(self, session: str, section: str, values: dict[str, str]) -> None:
        self._rpc_call(
            session=session,
            object_name="uci",
            method="set",
            params={"config": "firewall", "section": section, "values": values},
        )

    def _uci_delete(self, session: str, section: str) -> None:
        self._rpc_call(
            session=session,
            object_name="uci",
            method="delete",
            params={"config": "firewall", "section": section},
        )

    def _uci_apply(self, session: str) -> None:
        self._rpc_call(
            session=session,
            object_name="uci",
            method="apply",
            params={"rollback": False},
        )
