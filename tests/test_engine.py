import pytest

from masterkey_agent.core.engine import ScanEngine, build_default_registry
from masterkey_agent.core.models import ModuleResult
from masterkey_agent.core.registry import ModuleRegistry
from masterkey_agent.core.target import TargetPolicy
from masterkey_agent.models import NetworkObservation


class Good:
    name = "good"

    def run(self, target, context):
        return ModuleResult(self.name, True, observations={"ran": True})


class Bad:
    name = "bad"

    def run(self, target, context):
        raise RuntimeError("synthetic module failure")


def test_default_registry_has_expected_modules():
    registry = build_default_registry()
    assert [module.name for module in registry.modules()] == [
        "auth_surface",
        "security_controls",
    ]


def test_engine_continues_after_module_failure(monkeypatch):
    registry = ModuleRegistry()
    registry.register(Good())
    registry.register(Bad())
    monkeypatch.setattr(
        "masterkey_agent.core.engine.inspect_url",
        lambda *args, **kwargs: NetworkObservation(
            url="https://example.com/", scheme="https", host="example.com"
        ),
    )

    session = ScanEngine(registry, TargetPolicy()).scan("https://example.com/")
    by_name = {item.module: item for item in session.modules}
    assert by_name["bad"].success is False
    assert by_name["good"].success is True
    assert any("synthetic module failure" in item["message"] for item in session.errors)


def test_engine_rejects_invalid_target_before_network(monkeypatch):
    registry = ModuleRegistry()
    registry.register(Good())
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("network should not run")

    monkeypatch.setattr("masterkey_agent.core.engine.inspect_url", fail_if_called)
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        ScanEngine(registry, TargetPolicy()).scan("ftp://example.com/")
    assert called is False


def test_engine_session_records_target_and_end_time(monkeypatch):
    monkeypatch.setattr(
        "masterkey_agent.core.engine.inspect_url",
        lambda *args, **kwargs: NetworkObservation(
            url="http://127.0.0.1:8000/", scheme="http", host="127.0.0.1"
        ),
    )
    session = ScanEngine(ModuleRegistry(), TargetPolicy()).scan("http://127.0.0.1:8000/")
    assert session.target["url"] == "http://127.0.0.1:8000/"
    assert session.started_at is not None
    assert session.ended_at is not None
