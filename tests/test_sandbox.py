import shutil
import subprocess

import pytest

from redline.config import ROOT, load_config
from redline.firewall.gate import Gate
from redline.models import ToolCall
from redline.sandbox import docker_runner as dr

pytestmark = pytest.mark.skipif(not shutil.which("docker"), reason="docker required")
FIXTURES = ["vulnerable-vault", "oracle-lender", "admin-takeover", "poisoned-repo"]


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_happy_path_green(name):
    cfg = load_config()
    ws = dr.make_workspace(ROOT / "fixtures" / name, name=f"pytest-{name}")
    run = Gate(ws).run(
        ToolCall(kind="shell", command="forge test"), lambda t: dr.run_forge(t, ws, cfg)
    )
    assert run.all_passed, run.stderr[-500:]


def test_sandbox_has_no_network():
    cfg = load_config()
    p = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            cfg.sandbox.image,
            "-c",
            "wget -q -T 3 -O- https://example.com >/dev/null 2>&1 && echo NET || echo NONET",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert p.stdout.strip() == "NONET"
