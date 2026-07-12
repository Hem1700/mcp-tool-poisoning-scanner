import os
import stat
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_install_hooks_copies_executable_pre_push_hook(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    install_script = _repo_root() / "scripts" / "install-hooks.sh"
    subprocess.run(
        ["bash", str(install_script)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    hook_path = tmp_path / ".git" / "hooks" / "pre-push"
    assert hook_path.exists()
    assert hook_path.stat().st_mode & stat.S_IXUSR


def test_pre_push_hook_blocks_on_failing_tests(tmp_path):
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    fake_pytest = fake_bin / "pytest"
    fake_pytest.write_text("#!/usr/bin/env bash\nexit 1\n")
    fake_pytest.chmod(0o755)

    hook_script = _repo_root() / "scripts" / "pre-push"
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    result = subprocess.run(["bash", str(hook_script)], env=env, capture_output=True, text=True)
    assert result.returncode == 1
    assert "Push blocked" in result.stdout + result.stderr


def test_pre_push_hook_allows_passing_tests(tmp_path):
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    fake_pytest = fake_bin / "pytest"
    fake_pytest.write_text("#!/usr/bin/env bash\nexit 0\n")
    fake_pytest.chmod(0o755)

    hook_script = _repo_root() / "scripts" / "pre-push"
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    result = subprocess.run(["bash", str(hook_script)], env=env, capture_output=True, text=True)
    assert result.returncode == 0
