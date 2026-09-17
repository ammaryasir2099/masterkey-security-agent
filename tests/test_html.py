from masterkey_agent.discovery.html import parse_public_html


def test_parse_public_html_extracts_form_metadata_without_values():
    html = '''<html><head><title>Sign in</title></head><body><form method="post" action="/login"><input name="email" type="email" autocomplete="username" value="secret@example.test"><input name="password" type="password" autocomplete="current-password" value="SuperSecret123!"></form></body></html>'''
    result = parse_public_html(html)
    assert result.title == "Sign in"
    assert len(result.forms) == 1
    assert result.forms[0].method == "POST"
    assert result.forms[0].action == "/login"
    assert {field.name for field in result.forms[0].fields} == {"email", "password"}
    assert any(field.type == "password" for field in result.forms[0].fields)
    assert all(not hasattr(field, "value") for field in result.forms[0].fields)


def test_parse_public_html_handles_page_without_forms():
    result = parse_public_html("<html><head><title>Home</title></head><body>OK</body></html>")
    assert result.title == "Home"
    assert result.forms == []


def test_parse_public_html_strips_form_action_query_and_fragment():
    result = parse_public_html(
        '<form action="https://example.com/login?token=SUPERSECRET#secret"></form>'
    )
    assert result.forms[0].action == "https://example.com/login"
    assert "SUPERSECRET" not in str(result.to_dict())
    assert "secret" not in str(result.to_dict())


def test_parse_public_html_extracts_safe_page_metadata_and_resource_references():
    html = '''<html><head>
    <meta name="generator" content="Example CMS 9">
    <meta name="robots" content="index,follow">
    <meta name="description" content="Public landing page">
    <script src="/assets/app.js?v=SECRET"></script>
    <link rel="stylesheet" href="/assets/site.css#theme">
    </head><body>
    <a href="/login?next=/private#top">Login</a>
    <a href="https://cdn.example.test/app.js?token=SECRET">Asset</a>
    </body></html>'''

    result = parse_public_html(html, base_url="https://example.com/home")

    assert result.meta["generator"] == "Example CMS 9"
    assert result.meta["robots"] == "index,follow"
    assert "description" not in result.meta
    assert result.scripts == ["https://example.com/assets/app.js"]
    assert result.styles == ["https://example.com/assets/site.css"]
    assert result.links == [
        "https://example.com/login",
        "https://cdn.example.test/app.js",
    ]
    assert "SECRET" not in str(result.to_dict())
