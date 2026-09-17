from masterkey_agent.discovery.html import parse_public_html

def test_parse_public_html_extracts_form_metadata_without_values():
    html='''<html><head><title>Sign in</title></head><body><form method="post" action="/login"><input name="email" type="email" autocomplete="username" value="secret@example.test"><input name="password" type="password" autocomplete="current-password" value="SuperSecret123!"></form></body></html>'''
    result=parse_public_html(html)
    assert result.title=="Sign in"; assert len(result.forms)==1; assert result.forms[0].method=="POST"; assert result.forms[0].action=="/login"; assert {f.name for f in result.forms[0].fields}=={"email","password"}; assert any(f.type=="password" for f in result.forms[0].fields); assert all(not hasattr(f,"value") for f in result.forms[0].fields)

def test_parse_public_html_handles_page_without_forms():
    result=parse_public_html("<html><head><title>Home</title></head><body>OK</body></html>")
    assert result.title=="Home"; assert result.forms==[]
