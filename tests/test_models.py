from masterkey_agent.models import AuthMap, BrowserInfo, NetworkObservation, SystemInfo

def test_system_info_to_dict():
    info=SystemInfo(os_name="Windows",platform="win32",release="10",hostname="lab")
    assert info.to_dict()["hostname"]=="lab"

def test_auth_map_to_dict():
    amap=AuthMap(protocols=["HTTPS/TLS"],indicators=["OAuth/OIDC-like redirect"],confidence="medium")
    assert amap.to_dict()["confidence"]=="medium"

def test_other_models_construct():
    browser=BrowserInfo(name="Chrome",executable="C:/Chrome.exe",version=None); observation=NetworkObservation(url="https://example.test/",scheme="https",host="example.test")
    assert browser.to_dict()["name"]=="Chrome"; assert observation.to_dict()["host"]=="example.test"
