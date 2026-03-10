from __future__ import annotations

from django import forms
from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import LoginView


class RememberMeAuthenticationForm(AuthenticationForm):
    remember_me = forms.BooleanField(required=False, initial=True)


class RememberMeLoginView(LoginView):
    authentication_form = RememberMeAuthenticationForm
    template_name = "registration/login.html"

    def form_valid(self, form: RememberMeAuthenticationForm):
        response = super().form_valid(form)
        if form.cleaned_data.get("remember_me"):
            self.request.session.set_expiry(int(getattr(settings, "REMEMBER_ME_AGE", 60 * 60 * 24 * 365 * 2)))
        else:
            self.request.session.set_expiry(0)
        return response
