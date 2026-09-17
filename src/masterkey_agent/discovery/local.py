"""Safe local environment discovery.

Reports non-secret metadata only; it does not inspect browser profiles,
cookies, password stores, tokens, or credential material.
"""
from __future__ import annotations
import os
import platform
import shutil
from pathlib import Path
from masterkey_agent.models import BrowserInfo, SystemInfo

_BROWSER_EXECUTABLES = (("Chrome", ("chrome", "google-chrome", "google-chrome-stable")), ("Edge", ("msedge", "microsoft-edge")), ("Firefox", ("firefox",)))

def collect_system_info() -> SystemInfo:
    return SystemInfo(os_name=platform.system() or "Unknown", platform=platform.platform() or os.name, release=platform.release() or "Unknown", hostname=platform.node() or "Unknown")

def _windows_known_browser_paths() -> list[tuple[str, Path]]:
    roots = [Path(v) for k in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA") if (v := os.environ.get(k))]
    paths = []
    for root in roots:
        paths.extend([("Chrome", root / "Google/Chrome/Application/chrome.exe"), ("Edge", root / "Microsoft/Edge/Application/msedge.exe"), ("Firefox", root / "Mozilla Firefox/firefox.exe"), ("Brave", root / "BraveSoftware/Brave-Browser/Application/brave.exe")])
    return paths

def _version_from_executable(executable: str) -> str | None:
    return None

def detect_browsers() -> list[BrowserInfo]:
    found, seen = [], set()
    if platform.system() == "Windows":
        for name, path in _windows_known_browser_paths():
            if name not in seen and path.is_file():
                found.append(BrowserInfo(name=name, executable=str(path), version=_version_from_executable(str(path))))
                seen.add(name)
    for name, candidates in _BROWSER_EXECUTABLES:
        if name in seen: continue
        for candidate in candidates:
            executable = shutil.which(candidate)
            if executable:
                found.append(BrowserInfo(name=name, executable=str(Path(executable)), version=_version_from_executable(executable)))
                seen.add(name); break
    return found
