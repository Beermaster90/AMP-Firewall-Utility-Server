from __future__ import annotations

from ..base import (
    FirewallAction,
    FirewallActionResult,
    FirewallPortStatus,
    FirewallPortTarget,
    FirewallProvider,
    FirewallStatusResult,
)


class NoopFirewallProvider(FirewallProvider):
    provider_id = "noop"
    display_name = "No-op (preview only)"

    def apply(self, action: FirewallAction, target: FirewallPortTarget) -> FirewallActionResult:
        return FirewallActionResult(
            success=True,
            provider_id=self.provider_id,
            action=action,
            target=target,
            message=(
                f"Preview: would {action.value} {target.port}/{target.protocol.upper()} "
                f"for instance {target.instance_name}"
            ),
            command=None,
        )

    def get_status(self, target: FirewallPortTarget) -> FirewallStatusResult:
        return FirewallStatusResult(
            provider_id=self.provider_id,
            target=target,
            status=FirewallPortStatus.UNKNOWN,
            message="No-op provider does not read firewall rules.",
        )
