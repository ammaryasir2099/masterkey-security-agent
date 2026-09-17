from masterkey_agent.core.models import ModuleResult
from masterkey_agent.core.registry import ModuleRegistry


class DummyB:
    name = "b"

    def run(self, target, context):
        return ModuleResult(self.name, True)


class DummyA:
    name = "a"

    def run(self, target, context):
        return ModuleResult(self.name, True)


def test_registry_returns_modules_in_deterministic_order():
    registry = ModuleRegistry()
    registry.register(DummyB())
    registry.register(DummyA())
    assert [module.name for module in registry.modules()] == ["a", "b"]


def test_registry_rejects_duplicate_names():
    registry = ModuleRegistry()
    registry.register(DummyA())
    try:
        registry.register(DummyA())
    except ValueError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("duplicate registration should fail")
