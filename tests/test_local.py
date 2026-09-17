from masterkey_agent.discovery.local import collect_system_info

def test_collect_system_info_returns_basic_metadata():
    info=collect_system_info(); assert info.os_name; assert info.platform; assert info.hostname

def test_detect_browsers_uses_executable_presence(monkeypatch):
    from masterkey_agent.discovery import local
    monkeypatch.setattr(local.shutil,"which",lambda name:"C:/Program Files/Browser/browser.exe" if name=="chrome" else None)
    assert any(b.name=="Chrome" for b in local.detect_browsers())

def test_detect_browsers_finds_windows_installation_path(monkeypatch,tmp_path):
    from masterkey_agent.discovery import local
    chrome=tmp_path/"Google"/"Chrome"/"Application"/"chrome.exe"; chrome.parent.mkdir(parents=True); chrome.write_bytes(b"")
    monkeypatch.setattr(local.platform,"system",lambda:"Windows"); monkeypatch.setattr(local,"_windows_known_browser_paths",lambda:[("Chrome",chrome)]); monkeypatch.setattr(local.shutil,"which",lambda _name:None)
    browsers=local.detect_browsers(); assert [b.name for b in browsers]==["Chrome"]; assert browsers[0].executable==str(chrome)

def test_detect_browsers_does_not_need_path_lookup_on_windows(monkeypatch,tmp_path):
    from masterkey_agent.discovery import local
    edge=tmp_path/"Microsoft"/"Edge"/"Application"/"msedge.exe"; edge.parent.mkdir(parents=True); edge.write_bytes(b"")
    monkeypatch.setattr(local.platform,"system",lambda:"Windows"); monkeypatch.setattr(local,"_windows_known_browser_paths",lambda:[("Edge",edge)]); monkeypatch.setattr(local.shutil,"which",lambda _name:None)
    assert any(b.name=="Edge" for b in local.detect_browsers())
