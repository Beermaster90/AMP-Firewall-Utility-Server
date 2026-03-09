from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="ports-index"),
    path("apply", views.apply_port_action, name="ports-apply"),
    path("apply-bulk", views.apply_bulk_action, name="ports-apply-bulk"),
    path("apply-orphan", views.apply_orphan_action, name="ports-apply-orphan"),
    path("apply-orphan-bulk", views.apply_orphan_bulk_action, name="ports-apply-orphan-bulk"),
    path("providers", views.provider_config, name="ports-providers"),
]
