# Copyright (c) 2021-2026 TurnkeyLinux <admin@turnkeylinux.org>
#
# turnkey-chroot is open source software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
"""Set up, run commands within, and tear down a chroot."""

import logging
import os
import shlex
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from os.path import abspath, join, realpath

log_levels = {
    "DEBUG": logging.DEBUG,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "ERROR": logging.ERROR,
    "ERR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "FATAL": logging.CRITICAL,
}

logger = logging.getLogger("chroot")

env_log_level = os.getenv("CHROOT_LOG_LEVEL", "warn").upper()
if "DEBUG" in os.environ:
    log_level = logging.DEBUG
elif env_log_level in log_levels:
    log_level = log_levels[env_log_level]
else:
    log_level = logging.WARNING

logging.basicConfig(
    format="%(asctime)s - [%(levelname)-7s]%(filename)s:%(lineno)d"
    " %(message)s",
    level=log_level,
)

MNT_DEFAULT = {
    # Mount types, rather than bind mounts - note /dev always needs bind mount
    "switch": "--type",
    # mount_type/host_mount: mount_point
    "proc": "proc",
    "sysfs": "sys",
    "dev": "dev",
    "devpts": "dev/pts",
    "tmpfs": "run",
}

MNT_FULL = {
    # Bind mounts /dev, /sys, /proc & /run into the chroot
    "switch": "--bind",
    # label/host_mount: mount_point
    "proc": "proc",
    "dev": "dev",
    "sys": "sys",
    "run": "run",
}


class ChrootError(Exception):
    pass


class MountError(ChrootError):
    pass


def is_mounted(path: str | os.PathLike) -> bool:
    """Determine if a given path is currently mounted.

    This method supports any path-like object - any object which implements the
    os.PathLike interface, this includes `str` and pathlib.Path objects.
    """
    _debug = f"chroot.is_mounted({path=})"
    raw_path: str = os.fspath(str(path))
    with open("/proc/mounts") as fob:
        for line in fob:
            _, guest, *_ = line.split()
            if guest == raw_path:
                logger.debug("%s: True", _debug)
                return True
    logger.debug("%s: False", _debug)
    return False


@contextmanager
def mount(
    target: str | os.PathLike,
    environ: dict[str, str] | None = None,
    mnt_profile: dict[str, str] | None = None,
    # On python <v3.13 (pre PEP 696) mypy will show:
    # "Generator" expects 3 type arguments, but 1 given [type-arg]
) -> Generator["Chroot"]:
    """Magic mount context manager.

    Usage:

        >>> with chroot.mount('/path/to/chroot') as mnt:
        >>>     assert mnt.path == '/path/to/chroot'
        >>>     assert mnt.run(['ls', '-la', '/proc']).returncode == 1
        >>>     assert os.path.exists('/path/to/chroot/proc')

    Args:
        target (os.PathLike):
            either a `MagicMounts` object or a path
        environ (dict[str, str] | None):
            a optional dictionary of env vars to pass to subprocess (default
            None - use host env)
        mnt_profile (dict[str, str] | None = None):
            an optional dictionary representing a mount profile

    Yields:
        a `Chroot` object representing a mounted chroot at the given location

    """
    logger.debug(
        "\nchroot.mount(\n  target=%s,\n  environ=%s,\n  mnt_profile=%s\n)",
        target,
        environ,
        mnt_profile,
    )
    chroot = Chroot(target, environ, mnt_profile)
    try:
        yield chroot
    finally:
        logger.debug(
            "chroot.mount(\n  target=%s,\n  environ=%s,\n  mnt_profile=%s\n)",
            target,
            environ,
            mnt_profile,
        )
        chroot.umount()


class MagicMounts:
    """MagicMounts: An object which manages mounting/unmounting a chroot.

    You *probably* don't want to use this object directly but rather the
    `mount` context manager, or the `Chroot` object.
    """

    _class = "chroot.MagicMounts"

    def __init__(self, mnt_profile: dict[str, str], root: str = "/") -> None:
        logger.debug(
            "\n%s(\n  mnt_profile=%s\n  root=%s\n)",
            self._class,
            mnt_profile,
            root,
        )
        root = os.fspath(abspath(root))

        self.switch = mnt_profile.pop("switch")
        self.profile = mnt_profile

        self.path: dict[str, str] = {}
        self.mounted: dict[str, bool] = {}
        for host_mount, chroot_mount in self.profile.items():
            self.path[host_mount] = join(root, chroot_mount)
            self.mounted[host_mount] = False

        self.mount()

    def mount(self) -> None:
        """Mount this chroot.

        Raises:
            MountError: An error occured while trying to mount chroot

        """
        _method = f"{self._class}.mount()"

        for host_mount, chroot_path in self.path.items():
            logger.debug(
                "%s - processing %s (%s)", _method, host_mount, chroot_path,
            )
            if is_mounted(chroot_path):
                logger.debug("{_method} - Mounted: {chroot_path=}")
                continue
            switch = self.switch
            if host_mount == "dev":
                switch = "--bind"  # dev should always be bind mounted
            command = ["mount", switch]
            if switch == "--type":
                if host_mount == "proc":
                    command.extend([host_mount, "proc", chroot_path])
                elif host_mount == "sysfs":
                    command.extend([host_mount, "sys", chroot_path])
                elif host_mount == "devpts":
                    command.extend([host_mount, "pts", chroot_path])
                elif host_mount == "tmpfs":
                    command.extend([host_mount, "tmpfs", chroot_path])
            elif switch == "--bind":
                command.extend([f"/{host_mount}", chroot_path])
            else:
                raise MountError(
                    f"Unknown switch passed to {_method}(): '{switch}'.",
                )
            try:
                logger.debug("%s - running '%s'", _method, " ".join(command))
                subprocess.run(command, check=True)
                self.mounted[host_mount] = True
            except subprocess.CalledProcessError as e:
                raise MountError(*e.args) from e

    def umount(self) -> None:
        """Un-mount this chroot.

        Raises:
            MountError: An error occured while trying to un-mount chroot

        """

        def _umount(path: str) -> None:
            logger.debug("%s.umount(path=%s)", self._class, path)
            try:
                subprocess.run(
                    ["/usr/bin/umount", "--force", path],
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise MountError from e

        for mount in self.mounted:
            if self.mounted[mount]:
                # when relevant, ensure <chroot>/dev/pts is unmounted before
                # trying to unmount <chroot>/dev
                if (
                    mount == "dev"
                    and "devpts" in self.path
                    and self.mounted["devpts"]
                ):

                    _umount(self.path["devpts"])
                    self.mounted["devpts"] = False
                _umount(self.path[mount])
                self.mounted[mount] = False

    def __del__(self) -> None:
        self.umount()

    def __repr__(self) -> str:
        _repr = [f"\n{self._class}("]
        for var, val in vars(self).items():
            if var.startswith("_"):
                continue
            _repr.append(f"  {var}={val},")
        return "\n".join(_repr) + "\n"


class Chroot:
    """A chroot object that you can run commands inside.

    This class automatically attempts to mount the given chroot.

    Example usage:

        >>> foo = Chroot("/path/to/chroot", {"ENVVAR": "bar"})
        >>> assert "ENVVAR=bar" in foo.run(["env"], text=True).stdout
    """

    _class = "chroot.Chroot"

    def __init__(
        self,
        newroot: str | os.PathLike,
        environ: dict[str, str] | None = None,
        mnt_profile: dict[str, str] | None = None,
    ) -> None:
        _p = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/bin:/usr/sbin"
        logger.debug(
            "%s(\n  newroot=%s,\n  environ=%s,\n mnt_profile=%s\n)",
            self._class,
            newroot,
            environ,
            mnt_profile,
        )
        if environ is None:
            environ = {}
        self.environ = {
            "HOME": "/root",
            "TERM": os.environ["TERM"],
            "LC_ALL": "C",
            "PATH": _p,
        }
        self.environ.update(environ)
        self.profile = (
            dict(MNT_DEFAULT) if not mnt_profile else dict(mnt_profile)
        )

        self.path: str = realpath(os.fspath(newroot))
        self.magicmounts = MagicMounts(self.profile, self.path)

    def _prepare_command(self, *commands: str) -> list[str]:
        if ">" in commands or "<" in commands or "|" in commands:
            raise ChrootError(
                "Output redirects and pipes not supported in"
                f"fab-chroot (command: `{commands}')",
            )
        quoted_commands = []
        for command in commands:
            try:
                quoted_commands.append(shlex.quote(command))
            except TypeError as e:
                raise ChrootError(
                    f"failed to prepare command {command!r} for chroot",
                ) from e
        return ["chroot", self.path, "sh", "-c", " ".join(quoted_commands)]

    def umount(self) -> None:
        self.magicmounts.umount()

    def system(self, command: str | None = None) -> int:
        """Execute system command in chroot.

        Roughly analagous to `os.system` except within the context of a chroot
        (uses subprocess internally).

        Args:
            command (str):
                (optional) command (as a string) to run inside a chroot
                    - if no command is passed, then will open an interactive
                      (bash) shell within the chroot

        Returns:
            int:
                returncode of process

        Raises:
            FileNotFoundError: chroot program doesn't exist

        """
        logger.debug(
            "%s.system (args) => %s", self._class, command)
        command_chroot = ["chroot", self.path, "/bin/bash"]
        if command:
            command_chroot.extend(["-c", command])
        logger.debug("%s.system: '%s')", self._class, " ".join(command_chroot))
        return subprocess.run(
            command_chroot, env=self.environ, check=False,
        ).returncode

    def run(
        self,
        command: str | list[str],
        *args: str,
        **kwargs: str | dict[str, str] | int | bool | None,
    ) -> subprocess.CompletedProcess:
        """Execute system command in chroot.

        Roughly analagous to `subprocess.run` except within the context of a
        chroot.

        Args:
            command (str):
                command to run inside a chroot followed by args as a list
                e.g. ``['ls', '-la', '/tmp']``

            *args: forwarded to subprocess.run
            **kwargs: forwarded to subprocess.run


        Returns:
            subprocess.CompletedProcess:
                The completed process object of the chroot call. Note: this
                applies to the `chroot` command, not the command to be run. As
                a result some attributes may be counter-intuitive.

        Raises:
            FileNotFoundError:
                chroot program doesn't exist
            CalledProcessError:
                check=True was passed in kwargs and exitcode != 0

        """
        logger.debug(
            "%s.run (args) => %s", self._class, repr(command),
        )
        if isinstance(command, str):
            command = command.split()
        cmd = self._prepare_command(*command)
        logger.debug(
            "%s.run (prepared cmd) => %s",
            self._class,
            repr(cmd),
        )
        # default check to False but allow callers to override via kwargs
        check = bool(kwargs.pop("check", False))
        # typing subprocess here is too complex, so ignore type error
        return subprocess.run(
            cmd,
            *args,
            env=self.environ,
            check=check,
            **kwargs,
        )  # type: ignore[call-overload]

    def __repr__(self) -> str:
        _repr = [f"\n{self._class}("]
        for var, val in vars(self).items():
            if var.startswith("_"):
                continue
            _repr.append(f"  {var}={val},")
        return "\n".join(_repr) + "\n"
