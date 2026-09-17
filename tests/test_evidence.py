from masterkey_agent.core.evidence import deduplicate_evidence, sanitize_url
from masterkey_agent.core.models import Evidence


def test_sanitize_url_removes_query_and_fragment():
    assert sanitize_url("https://example.com/account?token=SECRET#settings") == "https://example.com/account"


def test_evidence_serialization_redacts_query_and_fragment_from_target_url():
    evidence = Evidence(
        id="ev-1",
        source_module="links",
        evidence_type="link.destination",
        value="/account",
        target_url="https://example.com/page?session=SECRET#profile",
    )

    data = evidence.to_dict()

    assert data["target_url"] == "https://example.com/page"
    assert "SECRET" not in str(data)


def test_deduplicate_evidence_preserves_first_seen_order():
    first = Evidence("ev-1", "html", "link.destination", "/login", "https://example.com/")
    duplicate = Evidence("different-id", "html", "link.destination", "/login", "https://example.com/")
    second = Evidence("ev-2", "html", "link.destination", "/help", "https://example.com/")

    result = deduplicate_evidence([first, duplicate, second])

    assert result == [first, second]


def test_deduplicate_evidence_distinguishes_metadata():
    first = Evidence(
        "ev-1", "security", "header.csp", "present", "https://example.com/", {"directive": "default-src"}
    )
    second = Evidence(
        "ev-2", "security", "header.csp", "present", "https://example.com/", {"directive": "frame-ancestors"}
    )

    assert deduplicate_evidence([first, second]) == [first, second]
