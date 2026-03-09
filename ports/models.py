from django.db import models

from .security import decrypt_secret, encrypt_secret


class DiscoveredInstance(models.Model):
    instance_id = models.CharField(max_length=64, unique=True)
    instance_name = models.CharField(max_length=255)
    friendly_name = models.CharField(max_length=255, blank=True, default="")
    module = models.CharField(max_length=128, blank=True, default="")
    running = models.BooleanField(default=False)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["instance_name"]

    def __str__(self) -> str:
        return f"{self.instance_name} ({self.instance_id})"


class DiscoveredPort(models.Model):
    instance = models.ForeignKey(DiscoveredInstance, on_delete=models.CASCADE, related_name="ports")
    port = models.PositiveIntegerField()
    protocol = models.IntegerField()
    protocol_name = models.CharField(max_length=16, default="")
    name = models.CharField(max_length=255, blank=True, default="")
    description = models.CharField(max_length=255, blank=True, default="")
    required = models.BooleanField(null=True, blank=True)
    listening = models.BooleanField(null=True, blank=True)
    verified = models.BooleanField(null=True, blank=True)
    is_user_defined = models.BooleanField(null=True, blank=True)
    is_firewall_target = models.BooleanField(null=True, blank=True)
    range = models.IntegerField(null=True, blank=True)
    network_raw = models.JSONField(null=True, blank=True)
    core_raw = models.JSONField(null=True, blank=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["port", "protocol"]
        constraints = [
            models.UniqueConstraint(
                fields=["instance", "port", "protocol"],
                name="uniq_discovered_port_per_instance",
            )
        ]

    def __str__(self) -> str:
        return f"{self.instance.instance_name} {self.port}/{self.protocol_name}"


class FirewallProviderConfig(models.Model):
    provider_id = models.CharField(max_length=64, unique=True)
    enabled = models.BooleanField(default=False)
    openwrt_rpc_url = models.CharField(max_length=255, blank=True, default="")
    openwrt_username = models.CharField(max_length=128, blank=True, default="")
    openwrt_password_encrypted = models.TextField(blank=True, default="")
    openwrt_source_zone = models.CharField(max_length=64, blank=True, default="publicinternal")
    openwrt_forward_source_zone = models.CharField(max_length=64, blank=True, default="wan")
    openwrt_forward_dest_zone = models.CharField(max_length=64, blank=True, default="publicinternal")
    openwrt_forward_dest_ip = models.CharField(max_length=128, blank=True, default="")
    openwrt_manage_mode = models.CharField(max_length=32, blank=True, default="redirect")
    openwrt_aggressive_mode = models.BooleanField(default=True)
    openwrt_name_prefix = models.CharField(max_length=128, blank=True, default="arksa-ports-web")
    openwrt_display_prefix = models.CharField(max_length=64, blank=True, default="AMP:")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["provider_id"]

    def __str__(self) -> str:
        state = "enabled" if self.enabled else "disabled"
        return f"{self.provider_id} ({state})"

    def set_openwrt_password(self, raw_password: str) -> None:
        self.openwrt_password_encrypted = encrypt_secret(str(raw_password or ""))

    def get_openwrt_password(self) -> str:
        return decrypt_secret(self.openwrt_password_encrypted)


class AMPConnectionConfig(models.Model):
    config_key = models.CharField(max_length=32, unique=True, default="default")
    url = models.CharField(max_length=255, blank=True, default="")
    username = models.CharField(max_length=128, blank=True, default="")
    password_encrypted = models.TextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["config_key"]

    def __str__(self) -> str:
        return f"AMP connection ({self.config_key})"

    def set_password(self, raw_password: str) -> None:
        self.password_encrypted = encrypt_secret(str(raw_password or ""))

    def get_password(self) -> str:
        return decrypt_secret(self.password_encrypted)
