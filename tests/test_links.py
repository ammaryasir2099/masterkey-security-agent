from masterkey_agent.discovery.links import extract_public_links


def test_extract_public_links_normalizes_relative_absolute_and_deduplicates():
    html = '''<a href="/login?next=/private#top">one</a>
    <a href="https://example.com/help#faq">two</a>
    <a href="/login?different=1">duplicate path</a>
    <a href="mailto:user@example.com">mail</a>
    <a href="javascript:void(0)">script</a>'''

    result = extract_public_links(html, "https://example.com/app/index")

    assert result == ["https://example.com/login", "https://example.com/help"]


def test_extract_public_links_removes_userinfo_query_and_fragment():
    html = '<a href="https://user:password@example.com/account?token=SECRET#profile">account</a>'

    result = extract_public_links(html, "https://example.com/")

    assert result == ["https://example.com/account"]
    assert "SECRET" not in str(result)
    assert "password" not in str(result)
