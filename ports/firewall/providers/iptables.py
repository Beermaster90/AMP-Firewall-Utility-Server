from __future__ import annotations

import shlex

from django.conf import settings

from ..base import FirewallAction, FirewallActionResult, FirewallPortStatus, FirewallPortTarget, FirewallStatusResult
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

    def _has_matching_accept_rule(self, target: FirewallPortTarget) -> tuple[bool, str]:
        proto = self._protocol(target.protocol)
        ok, stdout, stderr = self._run([self.binary_name, "-S", "INPUT"])
        if not ok:
            return False, (stderr.strip() or "Unable to query iptables INPUT chain.")

        proto_token = f"-p {proto}"
        port_token = f"--dport {target.port}"
        for line in stdout.splitlines():
            s = line.strip()
            if not s.startswith("-A INPUT "):
                continue
            if proto_token in s and port_token in s and "-j ACCEPT" in s:
                return True, ""
        return False, ""

    def _delete_all_matching_accept_rules(self, target: FirewallPortTarget) -> tuple[int, str]:
        proto = self._protocol(target.protocol)
        ok, stdout, stderr = self._run([self.binary_name, "-S", "INPUT"])
        if not ok:
            return 0, (stderr.strip() or "Unable to query iptables INPUT chain.")

        proto_token = f"-p {proto}"
        port_token = f"--dport {target.port}"
        matching_lines: list[str] = []
        for line in stdout.splitlines():
            s = line.strip()
            if not s.startswith("-A INPUT "):
                continue
            if proto_token in s and port_token in s and "-j ACCEPT" in s:
                matching_lines.append(s)

        removed = 0
        for rule_line in matching_lines:
            try:
                tokens = shlex.split(rule_line)
            except ValueError:
                return removed, f"Unable to parse iptables rule: {rule_line}"
            if len(tokens) < 2:
                continue
            # Convert exact `-A INPUT ...` line to `-D INPUT ...` to ensure exact delete.
            delete_cmd = [self.binary_name, "-D", tokens[1], *tokens[2:]]
            d_ok, _d_stdout, d_stderr = self._run(delete_cmd)
            if not d_ok:
                return removed, (d_stderr.strip() or "unknown error")
            removed += 1

        return removed, ""

    def apply(self, action: FirewallAction, target: FirewallPortTarget) -> FirewallActionResult:
        command = self.build_command(action=action, target=target)

        if not settings.FIREWALL_EXECUTE:
            return FirewallActionResult(
                success=True,
                provider_id=self.provider_id,
                action=action,
                target=target,
                message="Dry run only. Set FIREWALL_EXECUTE=1 to execute commands.",
                command=command,
            )

        if action is FirewallAction.ENABLE:
            exists, query_err = self._has_matching_accept_rule(target=target)
            if query_err:
                return FirewallActionResult(
                    success=False,
                    provider_id=self.provider_id,
                    action=action,
                    target=target,
                    message=f"Command failed: {query_err}",
                    command=command,
                )
            if exists:
                return FirewallActionResult(
                    success=True,
                    provider_id=self.provider_id,
                    action=action,
                    target=target,
                    message="Matching iptables ACCEPT rule already exists; no change needed.",
                    command=None,
                )
            return super().apply(action=action, target=target)

        removed, err = self._delete_all_matching_accept_rules(target=target)
        if err:
            return FirewallActionResult(
                success=False,
                provider_id=self.provider_id,
                action=action,
                target=target,
                message=f"Command failed: {err}",
                command=command,
            )
        if removed == 0:
            return FirewallActionResult(
                success=True,
                provider_id=self.provider_id,
                action=action,
                target=target,
                message="No matching iptables ACCEPT rule found; port was already closed.",
                command=None,
            )
        return FirewallActionResult(
            success=True,
            provider_id=self.provider_id,
            action=action,
            target=target,
            message=f"Removed {removed} matching iptables ACCEPT rule(s).",
            command=command,
        )

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

        # For per-port management UI we treat absence of a matching explicit rule as closed,
        # regardless of INPUT default policy. This keeps row state aligned with enable/disable
        # operations for managed entries.
        if default_policy == "ACCEPT":
            status = FirewallPortStatus.CLOSED
            msg = "No matching explicit iptables rule; port treated as closed for managed state (INPUT policy ACCEPT)."
        elif default_policy in {"DROP", "REJECT"}:
            status = FirewallPortStatus.CLOSED
            msg = "No matching explicit iptables rule; INPUT default policy blocks inbound."
        else:
            status = FirewallPortStatus.UNKNOWN
            msg = f"No matching explicit rule; INPUT default policy is {default_policy}."

        return FirewallStatusResult(
            provider_id=self.provider_id,
            target=target,
            status=status,
            message=msg,
        )
