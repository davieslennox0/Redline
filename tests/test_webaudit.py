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
