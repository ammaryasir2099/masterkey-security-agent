from masterkey_agent.core.target import normalize_target
from masterkey_agent.discovery.webmeta import WebMetadataModule
from masterkey_agent.models import HTMLField, HTMLForm, NetworkObservation, PublicHTML


def test_web_metadata_analyzes_existing_html_only():
    target = normalize_target("https://example.test/")
    html = PublicHTML(
        title="Home",
        forms=[HTMLForm(fields=[HTMLField(name="email", type="email")])],
        external_script_count=2,
        external_style_count=1,
        canonical_url="https://example.test/home",
        security_meta={"referrer": "strict-origin"},
    )
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        public_html=html,
    )
    result = WebMetadataModule().run(target, {"network": observation})
    assert result.observations["form_count"] == len(html.forms)
    assert result.observations["external_script_count"] == 2
    assert result.observations["external_style_count"] == 1
    assert result.observations["canonical_present"] is True
    assert all("value=" not in evidence.value.lower() for evidence in result.evidence)


def test_web_metadata_is_analysis_only_when_html_is_missing():
    target = normalize_target("https://example.test/")
    observation = NetworkObservation(url=target.url, scheme="https", host=target.hostname)
    result = WebMetadataModule().run(target, {"network": observation})
    assert result.success is True
    assert result.evidence == []
    assert result.observations["form_count"] == 0
