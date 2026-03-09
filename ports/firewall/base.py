from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class FirewallAction(str, Enum):
    ENABLE = "enable"
    DISABLE = "disable"


class FirewallPortStatus(str, Enum):
    OPEN = "Open"
    DISABLED = "Disabled"
    CLOSED = "Closed"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class FirewallPortTarget:
    instance_name: str
    port: int
    protocol: str
    instance_friendly_name: str = ""
    description: str = ""


@dataclass(frozen=True)
class FirewallActionResult:
    success: bool
    provider_id: str
    action: FirewallAction
    target: FirewallPortTarget
    message: str
    command: list[str] | None = None


@dataclass(frozen=True)
class FirewallStatusResult:
    provider_id: str
    target: FirewallPortTarget
    status: FirewallPortStatus
    message: str


class FirewallProvider(ABC):
    provider_id: str
    display_name: str
    required_config_fields: tuple[str, ...] = ()
    local_provider: bool = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    @abstractmethod
    def apply(self, action: FirewallAction, target: FirewallPortTarget) -> FirewallActionResult:
        raise NotImplementedError

    @abstractmethod
    def get_status(self, target: FirewallPortTarget) -> FirewallStatusResult:
        raise NotImplementedError

    def has_required_config(self) -> bool:
        for key in self.required_config_fields:
            value = self.config.get(key)
            if value is None or str(value).strip() == "":
                return False
        return True

    def is_supported(self) -> tuple[bool, str]:
        return True, "Provider is available."

    def is_in_use(self) -> tuple[bool, str]:
        return True, "Provider usage state not restricted."
