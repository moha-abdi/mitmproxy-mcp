import os
from pathlib import Path
from unittest.mock import patch

import pytest

from mitmproxy_mcp import __main__ as cli


def _fake_targets(root: Path) -> dict[str, Path]:
    scripts_dir = root / "scripts"
    scripts_dir.mkdir()

    targets: dict[str, Path] = {}
    for command in cli.COMMANDS:
        target = scripts_dir / command
        target.write_text("binary", encoding="utf-8")
        targets[command] = target
    return targets


def test_install_shims_posix_creates_executable_shims(tmp_path: Path):
    targets = _fake_targets(tmp_path)
    bin_dir = tmp_path / "bin"

    with patch.object(cli, "_resolve_command_targets", return_value=targets):
        created = cli.install_shims(bin_dir=bin_dir, force=False, is_windows=False)

    assert len(created) == 3
    for command, target in targets.items():
        shim = bin_dir / command
        assert shim in created
        content = shim.read_text(encoding="utf-8")
        assert content == f'#!/usr/bin/env sh\nexec "{target}" "$@"\n'
        assert os.access(shim, os.X_OK)


def test_install_shims_windows_creates_cmd_files(tmp_path: Path):
    targets = _fake_targets(tmp_path)
    bin_dir = tmp_path / "bin"

    with patch.object(cli, "_resolve_command_targets", return_value=targets):
        created = cli.install_shims(bin_dir=bin_dir, force=False, is_windows=True)

    assert len(created) == 3
    for command, target in targets.items():
        shim = bin_dir / f"{command}.cmd"
        assert shim in created
        content = shim.read_text(encoding="utf-8")
        assert content == f'@echo off\n"{target}" %*\n'


def test_install_shims_requires_force_to_overwrite(tmp_path: Path):
    targets = _fake_targets(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "mitmproxy").write_text("old", encoding="utf-8")

    with patch.object(cli, "_resolve_command_targets", return_value=targets):
        with pytest.raises(FileExistsError):
            cli.install_shims(bin_dir=bin_dir, force=False, is_windows=False)


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics vary on Windows")
def test_install_shims_force_replaces_broken_symlink(tmp_path: Path):
    targets = _fake_targets(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    broken_target = tmp_path / "missing" / "mitmproxy"
    (bin_dir / "mitmproxy").symlink_to(broken_target)

    with patch.object(cli, "_resolve_command_targets", return_value=targets):
        created = cli.install_shims(bin_dir=bin_dir, force=True, is_windows=False)

    shim = bin_dir / "mitmproxy"
    assert shim in created
    assert shim.read_text(encoding="utf-8") == (
        f'#!/usr/bin/env sh\nexec "{targets["mitmproxy"]}" "$@"\n'
    )


def test_main_install_shims_command(tmp_path: Path):
    targets = _fake_targets(tmp_path)
    bin_dir = tmp_path / "bin"

    with patch.object(cli, "_resolve_command_targets", return_value=targets):
        code = cli.main(["install-shims", "--bin-dir", str(bin_dir)])

    assert code == 0
    assert (bin_dir / "mitmproxy").exists()


def test_main_without_command_prints_help(capsys: pytest.CaptureFixture[str]):
    code = cli.main([])
    output = capsys.readouterr().out

    assert code == 0
    assert "install-shims" in output
