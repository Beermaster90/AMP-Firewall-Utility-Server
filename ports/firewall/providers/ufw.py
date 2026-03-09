from __future__ import annotations

import re

from ..base import FirewallAction, FirewallPortStatus, FirewallPortTarget, FirewallStatusResult
from .shell_base import ShellCommandFirewallProvider


class UfwFirewallProvider(ShellCommandFirewallProvider):
    provider_id = "ufw"
    display_name = "UFW"
    binary_name = "/usr/sbin/ufw"

    def build_command(self, action: FirewallAction, target: FirewallPortTarget) -> list[str]:
        proto = self._protocol(target.protocol)
        port_spec = f"{target.port}/{proto}"
        if action is FirewallAction.ENABLE:
            return [self.binary_name, "allow", port_spec]
        return [self.binary_name, "delete", "allow", port_spec]

    def status_command(self, target: FirewallPortTarget) -> list[str]:
        return [self.binary_name, "status", "verbose"]

    def is_in_use(self) -> tuple[bool, str]:
        ok, stdout, stderr = self._run([self.binary_name, "status"])
        if not ok:
            return False, (stderr.strip() or "Unable to query ufw status.")
        text = stdout.lower()
        if "status: active" in text:
            return True, "UFW is active."
        return False, "UFW is installed but inactive."

    def parse_status(self, target: FirewallPortTarget, stdout: str) -> FirewallStatusResult:
        text = stdout.lower()
        if "status: inactive" in text:
            return FirewallStatusResult(
                provider_id=self.provider_id,
                target=target,
                status=FirewallPortStatus.UNKNOWN,
                message="UFW is inactive.",
            )

        proto = self._protocol(target.protocol)
        pattern = re.compile(rf"\b{target.port}/{re.escape(proto)}\b")
        has_allow = False
        has_deny = False
        for line in stdout.splitlines():
            lowered = line.lower()
            if not pattern.search(lowered):
                continue
            if "allow" in lowered:
                has_allow = True
            if "deny" in lowered or "reject" in lowered:
                has_deny = True

        if has_deny:
            return FirewallStatusResult(
                provider_id=self.provider_id,
                target=target,
                status=FirewallPortStatus.CLOSED,
                message="Matching UFW deny/reject rule found.",
            )
        if has_allow:
            return FirewallStatusResult(
                provider_id=self.provider_id,
                target=target,
                status=FirewallPortStatus.OPEN,
                message="Matching UFW allow rule found.",
            )

        if "default: allow (incoming)" in text:
            status = FirewallPortStatus.OPEN
            msg = "No specific rule, but UFW default incoming policy is allow."
        else:
            status = FirewallPortStatus.CLOSED
            msg = "No matching UFW allow rule found."
        return FirewallStatusResult(
            provider_id=self.provider_id,
            target=target,
            status=status,
            message=msg,
        )
