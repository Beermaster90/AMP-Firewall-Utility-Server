from __future__ import annotations

from ..base import FirewallAction, FirewallPortStatus, FirewallPortTarget, FirewallStatusResult
from .shell_base import ShellCommandFirewallProvider


class IptablesFirewallProvider(ShellCommandFirewallProvider):
    provider_id = "iptables"
    display_name = "iptables"
    binary_name = "/usr/sbin/iptables"

    def build_command(self, action: FirewallAction, target: FirewallPortTarget) -> list[str]:
        proto = self._protocol(target.protocol)
        op = "-I" if action is FirewallAction.ENABLE else "-D"
        return [
            self.binary_name,
            op,
            "INPUT",
            "-p",
            proto,
            "--dport",
            str(target.port),
            "-j",
            "ACCEPT",
        ]

    def status_command(self, target: FirewallPortTarget) -> list[str]:
        return [self.binary_name, "-S", "INPUT"]

    def is_in_use(self) -> tuple[bool, str]:
        ok, stdout, stderr = self._run([self.binary_name, "-S", "INPUT"])
        if not ok:
            return False, (stderr.strip() or "Unable to query iptables INPUT chain.")

        default_policy = "ACCEPT"
        has_input_rules = False
        for line in stdout.splitlines():
            s = line.strip()
            if s.startswith("-P INPUT "):
                default_policy = s.split()[-1].upper()
            if s.startswith("-A INPUT "):
                has_input_rules = True

        if has_input_rules or default_policy in {"DROP", "REJECT"}:
            return True, "iptables INPUT chain has active filtering rules."
        return False, "iptables present, but INPUT chain is effectively open/default."

    def parse_status(self, target: FirewallPortTarget, stdout: str) -> FirewallStatusResult:
        proto = self._protocol(target.protocol)
        port_token = f"--dport {target.port}"
        proto_token = f"-p {proto}"

        default_policy = "DROP"
        for line in stdout.splitlines():
            s = line.strip()
            if s.startswith("-P INPUT "):
                default_policy = s.split()[-1].upper()
                break

        for line in stdout.splitlines():
            s = line.strip()
            if proto_token in s and port_token in s:
                if "-j ACCEPT" in s:
                    return FirewallStatusResult(
                        provider_id=self.provider_id,
                        target=target,
                        status=FirewallPortStatus.OPEN,
                        message="Matching iptables ACCEPT rule found.",
                    )
                if "-j DROP" in s or "-j REJECT" in s:
                    return FirewallStatusResult(
                        provider_id=self.provider_id,
                        target=target,
                        status=FirewallPortStatus.CLOSED,
                        message="Matching iptables DROP/REJECT rule found.",
                    )

        if default_policy == "ACCEPT":
            status = FirewallPortStatus.OPEN
            msg = "No explicit port rule; INPUT default policy is ACCEPT."
        elif default_policy in {"DROP", "REJECT"}:
            status = FirewallPortStatus.CLOSED
            msg = "No explicit port rule; INPUT default policy blocks inbound."
        else:
            status = FirewallPortStatus.UNKNOWN
            msg = f"No explicit rule; INPUT default policy is {default_policy}."

        return FirewallStatusResult(
            provider_id=self.provider_id,
            target=target,
            status=status,
            message=msg,
        )
