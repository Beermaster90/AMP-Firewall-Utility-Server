from __future__ import annotations

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import DiscoveredInstance, DiscoveredPort
from .security import validate_management_url


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class SecurityHardeningTests(TestCase):
    def setUp(self) -> None:
        self.user = get_user_model().objects.create_user(username="tester", password="pw")

    def test_index_requires_login(self) -> None:
        response = self.client.get(reverse("ports-index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])

    def test_login_page_renders(self) -> None:
        response = self.client.get(reverse("login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sign In")
        self.assertContains(response, "Keep me signed in")

    def test_login_sets_long_session_when_remember_me_enabled(self) -> None:
        response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "pw",
                "remember_me": "1",
                "next": "/",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertGreaterEqual(self.client.session.get_expiry_age(), 60 * 60 * 24 * 365)

    def test_login_uses_browser_session_when_remember_me_disabled(self) -> None:
        response = self.client.post(
            reverse("login"),
            {
                "username": "tester",
                "password": "pw",
                "next": "/",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertEqual(self.client.session.get_expire_at_browser_close(), True)

    def test_index_uses_snapshot_by_default(self) -> None:
        self.client.force_login(self.user)
        instance = DiscoveredInstance.objects.create(
            instance_id="inst-1",
            instance_name="ark-server",
            friendly_name="Ark Server",
        )
        DiscoveredPort.objects.create(
            instance=instance,
            port=7777,
            protocol=6,
            protocol_name="tcp",
            name="Game Port",
            description="Game Port",
        )

        with patch("ports.views.AMPPortCollector.collect") as collect_mock:
            response = self.client.get(reverse("ports-index"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ark-server")
        collect_mock.assert_not_called()

    def test_index_syncs_only_when_requested(self) -> None:
        self.client.force_login(self.user)
        sync_result = Mock(
            instances_added=0,
            instances_removed=0,
            ports_added=0,
            ports_removed=0,
        )
        collector = Mock()
        collector.collect.return_value = []

        with patch("ports.views.AMPPortCollector", return_value=collector), patch(
            "ports.views.sync_discovered_data",
            return_value=sync_result,
        ):
            response = self.client.get(reverse("ports-index"), {"sync": "1"})

        self.assertEqual(response.status_code, 200)
        collector.collect.assert_called_once()

    def test_apply_action_rejects_undiscovered_target(self) -> None:
        self.client.force_login(self.user)

        provider = Mock()
        with patch("ports.views.get_provider", return_value=provider):
            response = self.client.post(
                reverse("ports-apply"),
                {
                    "provider_id": "iptables",
                    "action": "enable",
                    "instance_name": "not-real",
                    "instance_friendly_name": "",
                    "port": "7777",
                    "protocol": "tcp",
                    "description": "Game Port",
                },
            )

        self.assertEqual(response.status_code, 302)
        provider.apply.assert_not_called()

    def test_apply_action_uses_discovered_snapshot_target(self) -> None:
        self.client.force_login(self.user)
        instance = DiscoveredInstance.objects.create(
            instance_id="inst-1",
            instance_name="ark-server",
            friendly_name="Ark Server",
        )
        DiscoveredPort.objects.create(
            instance=instance,
            port=7777,
            protocol=6,
            protocol_name="tcp",
            name="Game Port",
            description="Actual Description",
        )

        provider = Mock()
        provider.apply.return_value.success = True
        provider.apply.return_value.message = "ok"
        provider.apply.return_value.command = None
        provider.get_status.return_value.status.value = "Open"
        provider.get_status.return_value.message = "Matching rule found."

        with patch("ports.views.get_provider", return_value=provider):
            response = self.client.post(
                reverse("ports-apply"),
                {
                    "provider_id": "iptables",
                    "action": "enable",
                    "instance_name": "ark-server",
                    "instance_friendly_name": "Tampered Friendly",
                    "port": "7777",
                    "protocol": "tcp",
                    "description": "Tampered Description",
                    "response_json": "1",
                },
            )

        self.assertEqual(response.status_code, 200)
        _, kwargs = provider.apply.call_args
        target = kwargs["target"]
        self.assertEqual(target.instance_friendly_name, "Ark Server")
        self.assertEqual(target.description, "Actual Description")

    def test_provider_config_rejects_public_amp_url(self) -> None:
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("ports-providers"),
            {
                "form_action": "save",
                "amp__url": "http://1.1.1.1:8080",
                "amp__username": "amp",
                "amp__password": "secret",
                "openwrt__rpc_url": "",
                "openwrt__username": "",
                "openwrt__password": "",
            },
            follow=True,
        )

        self.assertContains(response, "AMP URL is invalid")

    def test_orphan_delete_rejects_unmanaged_section(self) -> None:
        self.client.force_login(self.user)
        provider = Mock()
        provider.provider_id = "openwrt"
        provider.list_managed_rules.return_value = []

        with patch("ports.views.get_provider", return_value=provider):
            response = self.client.post(
                reverse("ports-apply-orphan"),
                {
                    "provider_id": "openwrt",
                    "action": "delete",
                    "section": "cfg123",
                },
            )

        self.assertEqual(response.status_code, 302)
        provider.delete_rule_by_section.assert_not_called()


class ManagementUrlValidationTests(TestCase):
    def test_rejects_public_ip_url(self) -> None:
        with self.assertRaisesMessage(ValueError, "public"):
            validate_management_url("http://1.1.1.1/ubus", setting_name="OPENWRT_ALLOWED_HOSTS")
