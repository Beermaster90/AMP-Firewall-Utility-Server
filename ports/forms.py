from __future__ import annotations

from django import forms

from .firewall.base import FirewallAction
from .firewall.registry import provider_choices


class PortActionForm(forms.Form):
    provider_id = forms.ChoiceField(choices=(), required=True)
    action = forms.ChoiceField(
        choices=[(FirewallAction.ENABLE.value, "Enable"), (FirewallAction.DISABLE.value, "Disable")],
        required=True,
    )
    instance_name = forms.CharField(max_length=255, required=True)
    instance_friendly_name = forms.CharField(max_length=255, required=False)
    port = forms.IntegerField(min_value=1, max_value=65535, required=True)
    protocol = forms.CharField(max_length=16, required=True)
    description = forms.CharField(max_length=255, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["provider_id"].choices = list(provider_choices(only_available=True))


class PortListFilterForm(forms.Form):
    include_ads = forms.BooleanField(required=False)
    active_only = forms.BooleanField(required=False)
    provider_id = forms.ChoiceField(choices=(), required=False)
    filter_field = forms.ChoiceField(
        choices=[("name", "Name"), ("description", "Description")],
        required=False,
    )
    filter_query = forms.CharField(max_length=120, required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = list(provider_choices(only_available=True))
        self.fields["provider_id"].choices = choices
        if not self.data and choices:
            self.initial["provider_id"] = choices[0][0]
        if not self.data:
            self.initial["filter_field"] = "name"


class BulkPortActionForm(forms.Form):
    provider_id = forms.ChoiceField(choices=(), required=True)
    action = forms.ChoiceField(
        choices=[(FirewallAction.ENABLE.value, "Enable"), (FirewallAction.DISABLE.value, "Disable")],
        required=True,
    )
    targets_json = forms.CharField(required=True)
    return_provider_id = forms.CharField(required=False)
    return_include_ads = forms.CharField(required=False)
    return_filter_field = forms.CharField(required=False)
    return_filter_query = forms.CharField(required=False)
    return_active_only = forms.CharField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["provider_id"].choices = list(provider_choices(only_available=True))


class OrphanRuleActionForm(forms.Form):
    provider_id = forms.ChoiceField(choices=(), required=True)
    action = forms.ChoiceField(
        choices=[("disable", "Disable"), ("delete", "Delete")],
        required=True,
    )
    section = forms.CharField(required=True)
    return_provider_id = forms.CharField(required=False)
    return_include_ads = forms.CharField(required=False)
    return_filter_field = forms.CharField(required=False)
    return_filter_query = forms.CharField(required=False)
    return_active_only = forms.CharField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["provider_id"].choices = list(provider_choices(only_available=True))


class OrphanRuleBulkActionForm(forms.Form):
    provider_id = forms.ChoiceField(choices=(), required=True)
    action = forms.ChoiceField(
        choices=[("delete", "Delete")],
        required=True,
    )
    sections_json = forms.CharField(required=True)
    return_provider_id = forms.CharField(required=False)
    return_include_ads = forms.CharField(required=False)
    return_filter_field = forms.CharField(required=False)
    return_filter_query = forms.CharField(required=False)
    return_active_only = forms.CharField(required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["provider_id"].choices = list(provider_choices(only_available=True))
