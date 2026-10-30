import pytest
from fastapi.testclient import TestClient

from redline import webaudit
from redline.server import create_app


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://evil.com/a/b",
        "https://github.com/a",
        "file:///etc/passwd",
        "https://github.com/a/b;rm -rf /",
        "https://github.com.evil.com/a/b",
        "git@github.com:a/b.git",
        "https://github.com/a/b/../../c",
    ],
)
def test_rejects_bad_urls(url):
    with pytest.raises(webaudit.AuditRejected):
        webaudit.parse_url(url)


def test_accepts_github_urls():
    assert webaudit.parse_url("https://github.com/foundry-rs/forge-template") == (
        "foundry-rs",
        "forge-template",
    )
    assert webaudit.parse_url("https://github.com/a/b.git/") == ("a", "b")


def test_endpoint_rejects_and_can_be_disabled(monkeypatch):
    c = TestClient(create_app())
    assert c.post("/audit", json={"url": "https://evil.com/x/y"}).status_code == 422
    monkeypatch.setenv("REDLINE_WEB_AUDIT", "0")
    assert c.post("/audit", json={"url": "https://github.com/a/b"}).status_code == 403


def test_per_ip_limit_six_per_12h(monkeypatch):
    monkeypatch.setattr(
        webaudit, "_clone", lambda o, r: (_ for _ in ()).throw(webaudit.AuditRejected("stop here"))
    )
    webaudit._hits.clear()
    webaudit._busy.clear()
    for _ in range(6):
        with pytest.raises(webaudit.AuditRejected, match="stop here"):
            webaudit.submit("https://github.com/a/b", lambda *a: None, ip="1.2.3.4")
    with pytest.raises(webaudit.AuditRejected, match="per 12 hours") as e:
        webaudit.submit("https://github.com/a/b", lambda *a: None, ip="1.2.3.4")
    assert e.value.status == 429
    with pytest.raises(webaudit.AuditRejected, match="stop here"):  # another IP is unaffected
        webaudit.submit("https://github.com/a/b", lambda *a: None, ip="5.6.7.8")


def test_pin_offline_solc(tmp_path):
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nsolc_version = "0.8.19"\n[fmt]\nline_length = 100\n'
    )
    webaudit.pin_offline_solc(tmp_path)
    t = (tmp_path / "foundry.toml").read_text()
    assert 'solc = "/solc/solc"' in t and "0.8.19" not in t and 'src = "src"' in t
