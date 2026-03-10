from __future__ import annotations

import os
import subprocess
from shutil import which

from django.conf import settings

from ..base import (
    FirewallAction,
    FirewallActionResult,
    FirewallPortStatus,
    FirewallPortTarget,
    FirewallProvider,
    FirewallStatusResult,
)


class ShellCommandFirewallProvider(FirewallProvider):
    local_provider = True
    binary_name: str = ""
    use_sudo: bool = True
    @staticmethod
    def _protocol(protocol: str) -> str:
        value = protocol.lower().strip()
        if value in {"0", "tcp"}:
            return "tcp"
        if value in {"1", "udp"}:
            return "udp"
        return value

    def build_command(self, action: FirewallAction, target: FirewallPortTarget) -> list[str]:
        raise NotImplementedError

    def status_command(self, target: FirewallPortTarget) -> list[str]:
        raise NotImplementedError

    def _run(self, command: list[str]) -> tuple[bool, str, str]:
        if self.use_sudo:
            command = ["sudo", "-n", *command]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=float(getattr(settings, "FIREWALL_COMMAND_TIMEOUT", 10)),
            )
        except FileNotFoundError:
            return False, "", f"Command not found: {command[0]}"
        except subprocess.TimeoutExpired:
            return False, "", "Firewall command timed out."
        return completed.returncode == 0, completed.stdout or "", completed.stderr or ""

    def is_supported(self) -> tuple[bool, str]:
        if not self.binary_name:
            return False, "Provider binary is not configured."
        if os.path.sep in self.binary_name:
            if not os.path.isfile(self.binary_name) or not os.access(self.binary_name, os.X_OK):
                return False, f"Binary not found on localhost: {self.binary_name}"
        elif which(self.binary_name) is None:
            return False, f"Binary not found on localhost: {self.binary_name}"
        return True, f"Binary found: {self.binary_name}"

    def is_in_use(self) -> tuple[bool, str]:
        return True, "Local firewall provider is usable."

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

        ok, stdout, stderr = self._run(command)
        if not ok:
            err_msg = stderr.strip() or "unknown error"
            return FirewallActionResult(
                success=False,
                provider_id=self.provider_id,
                action=action,
                target=target,
                message=f"Command failed: {err_msg}",
                command=command,
            )

        stdout = stdout.strip()
        return FirewallActionResult(
            success=True,
            provider_id=self.provider_id,
            action=action,
            target=target,
            message=stdout or "Command executed successfully.",
            command=command,
        )

    def get_status(self, target: FirewallPortTarget) -> FirewallStatusResult:
        command = self.status_command(target=target)
        ok, stdout, stderr = self._run(command)
        if not ok:
            return FirewallStatusResult(
                provider_id=self.provider_id,
                target=target,
                status=FirewallPortStatus.UNKNOWN,
                message=(stderr.strip() or "Failed to query firewall status."),
            )
        return self.parse_status(target=target, stdout=stdout)

    def parse_status(self, target: FirewallPortTarget, stdout: str) -> FirewallStatusResult:
        raise NotImplementedError
