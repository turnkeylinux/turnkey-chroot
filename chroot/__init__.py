# Copyright (c) 2021 TurnkeyLinux <admin@turnkeylinux.org>
#
# turnkey-chroot is open source software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.

import os
from os.path import abspath, join, realpath
import shlex
import subprocess
from contextlib import contextmanager

from typing import Dict, Optional, Union, TypeVar, Generator, List, Any

AnyPath = TypeVar("AnyPath", str, os.PathLike)

MNT_DEFAULT = {
    # Mounts 'devpts' and 'proc' type mounts into the chroot
    "switch": "-t",  # use '-t' (type) switch with mount
    "proc": "proc",  # label/mount_type: mount_point
    "devpts": "dev/pts",
}

MNT_FULL = {
    # Bind mounts /dev, /sys, /proc & /run into the chroot
    "switch": "-o",  # use '-o (bind)' (option) switch with mount
    "proc": "proc",  # label/host_mount: mount_point
    "dev": "dev",
    "sys": "sys",
    "run": "run",
}


def debug(*s: Any) -> None:
    if os.getenv("TKL_CHROOT_DEBUG", ""):
        print(*s)


class ChrootError(Exception):
    pass


class MountError(ChrootError):
    pass


def is_mounted(path: AnyPath) -> bool:
    """determines if a given path is currently mounted.

    This method supports any path-like object (any object which implements the
    os.PathLike interface, this includes `str`, `bytes` and path objects
    provided by `pathlib` in the standard library.
    """
    raw_path: Union[str, bytes] = os.fspath(path)
    mode = "rb" if isinstance(raw_path, bytes) else "r"
    sep = b" " if isinstance(raw_path, bytes) else " "
    with open("/proc/mounts", mode) as fob:
        for line in fob:
            host, guest, *others = line.split(sep)
            if guest == path:
                return True
    return False


@contextmanager
def mount(
    target: os.PathLike,
    environ: Optional[Dict[str, str]] = None,
    mnt_profile: Optional[Dict[str, str]] = None,
) -> Generator["Chroot", None, None]:
    """magic mount context manager

    Usage:

        >>> with chroot.mount('/path/to/chroot') as mnt:
        >>>     assert mnt.path == '/path/to/chroot'
        >>>     assert mnt.run(['ls', '-la', '/proc']).returncode == 1
        >>>     assert os.path.exists('/path/to/chroot/proc')

    Args:
        target: either a `MagicMounts` object or a path

    Yields:
        a `Chroot` object representing a mounted chroot at the given location

    """
    yield Chroot(target, environ, mnt_profile)


class MagicMounts:
    """MagicMounts: An object which manages mounting/unmounting a chroot.

    You *probably* don't want to use this object directly but rather the `mount`
    context manager, or the `Chroot` object.
    """

    def __init__(self, mnt_profile: Dict[str, str], root: str = "/"):
        root = os.fspath(abspath(root))

        self.profile = mnt_profile

        self.path: Dict[str, str] = {}
        self.mounted: Dict[str, str] = {}
        for k, v in self.profile.items():
            if k != "switch":
                self.path[k] = join(root, v)
                self.mounted[k] = False

        self.mount()

    def mount(self) -> None:
        """mount this chroot

        Raises:
            MountError: An error occured while trying to mount chroot
        """
        for host_mnt, chr_path in self.path.items():
            if is_mounted(chr_path):
                continue
            switch = self.profile["switch"]
            command = ["mount", switch]
            if switch == "-o":
                command.extend(["bind", host_mnt, chr_path])
            elif switch == "-t":
                command.extend([host_mnt, f"{host_mnt}-chroot", chr_path])
            else:
                raise MountError(
                    f"Unknown switch passed to mount() method: '{switch}'."
                )
            try:
                subprocess.run(command, check=True)
                self.mounted[host_mnt] = True
            except subprocess.CalledProcessError as e:
                raise MountError(*e.args) from e

    def umount(self) -> None:
        """un-mount this chroot

        Raises:
            MountError: An error occured while trying to un-mount chroot
        """
        command = ["umount", "-f"]
        for mount in self.mounted.keys():
            if self.mounted[mount]:
                subprocess.run([*command, self.path[mount]])
                self.mounted[mount] = False

    def __del__(self) -> None:
        self.umount()


class Chroot:
    """represents a chroot on your system that you can run commands inside.
    This class automatically attempts to mount the given chroot.

    Example usage:

        >>> foo = Chroot('/path/to/chroot', { 'ENVVAR': 'bar' })
        >>> assert 'ENVVAR=bar' in foo.run(['env'], text=True).stdout
    """

    def __init__(
        self,
        newroot: AnyPath,
        environ: Optional[Dict[str, str]] = None,
        mnt_profile: Optional[Dict[str, str]] = None,
    ):
        if environ is None:
            environ = {}
        self.environ = {
            "HOME": "/root",
            "TERM": os.environ["TERM"],
            "LC_ALL": "C",
            "PATH": "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/bin:/usr/sbin",
        }
        self.environ.update(environ)
        self.profile = MNT_DEFAULT if not mnt_profile else mnt_profile

        self.path: str = realpath(os.fspath(newroot))
        self.magicmounts = MagicMounts(self.profile, self.path)

    def _prepare_command(self, *commands: str) -> List[str]:
        if ">" in commands or "<" in commands or "|" in commands:
            raise ChrootError(
                "Output redirects and pipes not supported in"
                f"fab-chroot (command: `{commands}')"
            )
        quoted_commands = []
        for command in commands:
            try:
                quoted_commands.append(shlex.quote(command))
            except TypeError as e:
                raise ChrootError(
                    f"failed to prepare command {command!r} for chroot"
                ) from e
        return ["chroot", self.path, "sh", "-c", " ".join(quoted_commands)]

    def system(self, command: Optional[str] = None) -> int:
        """execute system command in chroot

        roughly analagous to `os.system` except within the context of a chroot
        (uses subprocess internally)

        Args:
            command: command (with args) to run inside a chroot
                     - if no command is passed, then will open an interactive
                       (bash) shell within the chroot

        Returns:
            returncode of process as an int

        Raises:
            FileNotFoundError: chroot program doesn't exist
        """

        debug("chroot.system (args) => \x1b[34m", repr(command), "\x1b[0m")
        command_chroot = ["chroot", self.path, "/bin/bash"]
        if command:
            command_chroot.extend(["-c", command])
        return subprocess.run(command_chroot, env=self.environ).returncode

    def run(
        self, command: str, *args: Any, **kwargs: Any
    ) -> subprocess.CompletedProcess:
        """execute system command in chroot

        roughly analagous to `subprocess.run` except within the context of a
        chroot

        Args:
            command: command to run inside a chroot followed by args as a list
                e.g. ``['ls', '-la', '/tmp']``

            *args: forwarded to subprocess.run
            **kwargs: forwarded to subprocess.run


        Returns:
            The completed process object (`subprocess.CompletedProcess`) of
            the chroot call. Note: this applies to the `chroot` command, not
            the inner command. As a result some attributes of thi may be
            counter-intuitive.

        Raises:
            FileNotFoundError: chroot program doesn't exist
            CalledProcessError: check=True was passed in kwargs and
                exitcode != 0
        """
        debug("chroot.run (args) => \x1b[34m", repr(command), "\x1b[0m")
        cmd = self._prepare_command(*command)
        debug("chroot.run (prepared cmd) => \x1b[33m", repr(cmd), "\x1b[0m")
        return subprocess.run(cmd, env=self.environ, *args, **kwargs)
