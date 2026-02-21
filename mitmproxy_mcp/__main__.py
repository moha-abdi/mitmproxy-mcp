import argparse
import os
import stat
import sys
import sysconfig
from pathlib import Path
from typing import Dict, List, Optional, Sequence


COMMANDS = ("mitmproxy", "mitmdump", "mitmweb")


def _default_bin_dir() -> Path:
    if os.name == "nt":
        return Path.home() / "AppData" / "Local" / "mitmproxy-mcp" / "bin"
    return Path.home() / ".local" / "bin"


def _scripts_dir() -> Path:
    scripts_path = sysconfig.get_path("scripts")
    if not scripts_path:
        raise RuntimeError("Could not resolve Python scripts directory")
    return Path(scripts_path)


def _resolve_command_target(scripts_dir: Path, command: str) -> Path:
    candidates = [scripts_dir / command]
    if os.name == "nt":
        candidates.extend(
            [
                scripts_dir / f"{command}.exe",
                scripts_dir / f"{command}.cmd",
                scripts_dir / f"{command}.bat",
            ]
        )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise RuntimeError(
        f"Could not find '{command}' in scripts directory: {scripts_dir}. "
        "Install mitmproxy in this Python environment first."
    )


def _resolve_command_targets() -> Dict[str, Path]:
    scripts_dir = _scripts_dir()
    return {
        command: _resolve_command_target(scripts_dir, command) for command in COMMANDS
    }


def _render_posix_shim(target: Path) -> str:
    safe_target = str(target).replace('"', '\\"')
    return f'#!/usr/bin/env sh\nexec "{safe_target}" "$@"\n'


def _render_windows_shim(target: Path) -> str:
    safe_target = str(target).replace('"', '""')
    return f'@echo off\n"{safe_target}" %*\n'


def _shim_path(bin_dir: Path, command: str, is_windows: bool) -> Path:
    if is_windows:
        return bin_dir / f"{command}.cmd"
    return bin_dir / command


def _path_exists_or_symlink(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _path_contains_directory(directory: Path) -> bool:
    try:
        target = directory.expanduser().resolve()
    except OSError:
        target = directory.expanduser()

    for path_part in os.environ.get("PATH", "").split(os.pathsep):
        if not path_part:
            continue
        try:
            candidate = Path(path_part).expanduser().resolve()
        except OSError:
            candidate = Path(path_part).expanduser()
        if candidate == target:
            return True
    return False


def install_shims(
    bin_dir: Path, force: bool = False, is_windows: Optional[bool] = None
) -> List[Path]:
    if is_windows is None:
        is_windows = os.name == "nt"

    targets = _resolve_command_targets()
    bin_dir.mkdir(parents=True, exist_ok=True)

    created: List[Path] = []
    for command, target in targets.items():
        shim_path = _shim_path(bin_dir, command, is_windows)
        if _path_exists_or_symlink(shim_path):
            if not force:
                raise FileExistsError(
                    f"Shim already exists: {shim_path}. Re-run with --force to replace it."
                )
            if shim_path.is_dir() and not shim_path.is_symlink():
                raise RuntimeError(
                    f"Shim path is a directory: {shim_path}. Remove it and retry."
                )
            shim_path.unlink()

        content = (
            _render_windows_shim(target) if is_windows else _render_posix_shim(target)
        )
        shim_path.write_text(content, encoding="utf-8")

        if not is_windows:
            shim_path.chmod(
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IXOTH
            )

        created.append(shim_path)

    return created


def _install_shims_command(args: argparse.Namespace) -> int:
    try:
        created = install_shims(args.bin_dir, force=args.force)
    except (RuntimeError, FileExistsError) as e:
        print(f"mitmproxy-mcp: {e}", file=sys.stderr)
        return 1

    print("Installed command shims:")
    for shim in created:
        print(f"  {shim}")

    if not _path_contains_directory(args.bin_dir):
        print("\nNote: shim directory is not in PATH.")
        if os.name == "nt":
            print(
                "Add this directory to PATH and restart your terminal:\n"
                f"  {args.bin_dir}"
            )
        else:
            print(
                "Add this line to your shell profile and restart your terminal:\n"
                f'  export PATH="{args.bin_dir}:$PATH"'
            )

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mitmproxy-mcp",
        description="Utilities for setting up mitmproxy-mcp runtime commands.",
    )
    subparsers = parser.add_subparsers(dest="command")

    install_parser = subparsers.add_parser(
        "install-shims",
        help="Install mitmproxy/mitmdump/mitmweb shims to this environment",
    )
    install_parser.add_argument(
        "--bin-dir",
        type=Path,
        default=_default_bin_dir(),
        help="Directory where shims will be created",
    )
    install_parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing shim files if present",
    )
    install_parser.set_defaults(func=_install_shims_command)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    command_func = getattr(args, "func", None)
    if command_func is None:
        parser.print_help()
        return 0
    return int(command_func(args))


if __name__ == "__main__":
    raise SystemExit(main())
