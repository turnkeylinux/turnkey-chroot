"""Tests for the `chroot` module.

These tests deliberately avoid any real mounting or chrooting (both of which
need root and mutate system state). Instead `MagicMounts` and
`subprocess.run` are patched so we exercise the pure logic - argv
construction, command validation, mount/umount bookkeeping and the context
manager contract - in isolation.
"""

from __future__ import annotations

import subprocess
from typing import ClassVar
from unittest.mock import mock_open, patch

import pytest

import chroot


class DummyMagicMounts:
    """Stand-in for `MagicMounts` that records calls instead of mounting.

    `Chroot.__init__` instantiates `MagicMounts` (which would shell out to
    `mount`), so we swap in this no-op double to keep construction side-effect
    free while still letting us assert that `umount()` is reached.
    """

    instances: ClassVar[list[DummyMagicMounts]] = []

    def __init__(self, mnt_profile: dict[str, str], root: str = "/") -> None:
        self.profile = mnt_profile
        self.root = root
        self.umount_called = False
        DummyMagicMounts.instances.append(self)

    def mount(self) -> None:
        pass

    def umount(self) -> None:
        self.umount_called = True


@pytest.fixture
def patched_mounts(
    monkeypatch: pytest.MonkeyPatch,
) -> list[DummyMagicMounts]:
    """Patch out mounting and provide a TERM env var.

    `Chroot.__init__` reads `os.environ["TERM"]`, so we set it to avoid a
    KeyError on hosts/CI where TERM is unset. monkeypatch undoes the setattr
    automatically, so no explicit teardown is needed.
    """
    monkeypatch.setenv("TERM", "xterm")
    DummyMagicMounts.instances = []
    monkeypatch.setattr(chroot, "MagicMounts", DummyMagicMounts)
    return DummyMagicMounts.instances


def test_is_mounted_true() -> None:
    # second whitespace-separated field of each /proc/mounts line is the
    # mount point ("guest") the code matches against
    fake_mounts = (
        "proc /mnt/cr/proc proc rw 0 0\nsysfs /mnt/cr/sys sysfs rw 0 0\n"
    )
    with patch("builtins.open", mock_open(read_data=fake_mounts)):
        assert chroot.is_mounted("/mnt/cr/proc") is True


def test_is_mounted_false() -> None:
    fake_mounts = "proc /mnt/cr/proc proc rw 0 0\n"
    with patch("builtins.open", mock_open(read_data=fake_mounts)):
        assert chroot.is_mounted("/mnt/cr/sys") is False


def test_prepare_command_quotes_args(
    patched_mounts: list[DummyMagicMounts],
) -> None:
    cr = chroot.Chroot("/mnt/cr")
    cmd = cr._prepare_command("ls", "-la", "/tmp")
    # final element is the shell-quoted command string passed to `sh -c`
    assert cmd == ["chroot", "/mnt/cr", "sh", "-c", "ls -la /tmp"]


def test_prepare_command_shell_quoting(
    patched_mounts: list[DummyMagicMounts],
) -> None:
    cr = chroot.Chroot("/mnt/cr")
    # an arg containing a space must be quoted so it stays a single token
    cmd = cr._prepare_command("echo", "a b")
    assert cmd[-1] == "echo 'a b'"


@pytest.mark.parametrize("bad", [">", "<", "|"])
def test_prepare_command_rejects_redirects(
    patched_mounts: list[DummyMagicMounts],
    bad: str,
) -> None:
    cr = chroot.Chroot("/mnt/cr")
    # redirects/pipes can't be expressed safely through the argv-based
    # `chroot ... sh -c` invocation, so they must be refused
    with pytest.raises(chroot.ChrootError):
        cr._prepare_command("cat", bad, "file")


def test_run_builds_expected_argv(
    patched_mounts: list[DummyMagicMounts],
) -> None:
    captured_cmd: list[str] = []
    captured_kwargs: dict[str, object] = {}

    def fake_run(
        cmd: list[str],
        *args: object,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured_cmd.extend(cmd)
        captured_kwargs.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    cr = chroot.Chroot("/mnt/cr")
    with patch.object(chroot.subprocess, "run", fake_run):
        cr.run(["ls", "-la"])

    assert captured_cmd == ["chroot", "/mnt/cr", "sh", "-c", "ls -la"]
    # env is forced to the chroot's environ; check defaults to False
    assert captured_kwargs["env"] is cr.environ
    assert captured_kwargs["check"] is False


def test_run_check_override(
    patched_mounts: list[DummyMagicMounts],
) -> None:
    captured_kwargs: dict[str, object] = {}

    def fake_run(
        cmd: list[str],
        *args: object,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        captured_kwargs.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    cr = chroot.Chroot("/mnt/cr")
    with patch.object(chroot.subprocess, "run", fake_run):
        # caller-supplied check must survive the pop/re-pass and not raise a
        # duplicate-keyword TypeError
        cr.run(["true"], check=True)

    assert captured_kwargs["check"] is True


def test_mount_context_manager_unmounts(
    patched_mounts: list[DummyMagicMounts],
) -> None:
    with chroot.mount("/mnt/cr") as mnt:
        assert isinstance(mnt, chroot.Chroot)
        assert mnt.path == "/mnt/cr"
        # nothing unmounted while still inside the context
        assert patched_mounts[0].umount_called is False
    # leaving the context must trigger teardown via the finally block
    assert patched_mounts[0].umount_called is True
