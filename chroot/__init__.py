# Copyright (c) 2021-2025 TurnkeyLinux <admin@turnkeylinux.org>
#
# turnkey-chroot is open source software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.

import os
from os.path import abspath, join, realpath, exists
import shlex
import subprocess
import shutil
from contextlib import contextmanager

from typing import TypeVar, Generator, Any

AnyPath = TypeVar('AnyPath', str, os.PathLike)

MNT_DEFAULT = [
        # Mounts 'devpts' and 'proc' type mounts into the chroot
        ("-t", "proc", "proc"),
        ("-t", "sysfs", "sys"),
        ("-t", "devpts", "dev/pts"),
        ]

MNT_FULL = [
        # Bind mounts /dev, /sys, /proc & /run into the chroot
        ("--bind", "/proc", "proc"),
        ("--bind", "/sys", "sys"),
        ("--bind", "/dev", "dev"),
        ("--bind", "/dev/pts", "dev/pts"),
        ("--bind", "/run", "run"),
        ]

MNT_ARM_ON_AMD = (
        "--bind", "/proc/sys/fs/binfmt_misc", "proc/sys/fs/binfmt_misc")


def debug(*s: Any) -> None:
    if os.getenv('TKL_CHROOT_DEBUG', ''):
        print(*s)


class ChrootError(Exception):
    pass


class MountError(ChrootError):
    pass


def is_mounted(path: AnyPath) -> bool:
    ''' determines if a given path is currently mounted.

    This method supports any path-like object (any object which implements the
    os.PathLike interface, this includes `str`, `bytes` and path objects
    provided by `pathlib` in the standard library.
    '''
    raw_path: str | bytes = os.fspath(path)
    mode = 'rb' if isinstance(raw_path, bytes) else 'r'
    sep = b' ' if isinstance(raw_path, bytes) else ' '
    with open('/proc/mounts', mode) as fob:
        for line in fob:
            _, guest, *_ = line.split(sep)
            if guest == path:
                return True
    return False


@contextmanager
def mount(
        target: os.PathLike,
        environ: dict[str, str] | None = None,
        mnt_profile: list[tuple[str, str, str]] | None = None
) -> Generator['Chroot', None, None]:
    '''magic mount context manager

    Usage:

        >>> with chroot.mount('/path/to/chroot') as mnt:
        >>>     assert mnt.path == '/path/to/chroot'
        >>>     assert mnt.run(['ls', '-la', '/proc']).returncode == 1
        >>>     assert os.path.exists('/path/to/chroot/proc')

    Args:
        target: either a `MagicMounts` object or a path

    Yields:
        a `Chroot` object representing a mounted chroot at the given location

    '''
    yield Chroot(target, environ, mnt_profile)


class MagicMounts:
    '''MagicMounts: An object which manages mounting/unmounting a chroot.

    You *probably* don't want to use this object directly but rather the `mount`
    context manager, or the `Chroot` object.
    '''
    def __init__(self,
                 mnt_profile: list[tuple[str, str, str]],
                 root: str = "/",
                 ):
        #self.profile = mnt_profile if mnt_profile else MNT_DEFAULT
        self.profile = MNT_FULL
        root = os.fspath(abspath(root))
        self.qemu_arch_static = ()

        host_arch = os.getenv("HOST_ARCH")
        fab_arch = os.getenv("FAB_ARCH")
        if fab_arch:
            if not host_arch:
                raise ChrootError(
                        "If FAB_ARCH is set, HOST_ARCH is also required")
            elif host_arch and host_arch != fab_arch:
                # for now:
                # - assume that we're building arm64 on amd64
                # - override mnt_profile
                MNT_FULL.append(MNT_ARM_ON_AMD)
                self.profile = MNT_FULL
                qemu_arch_bin = "usr/bin/qemu-aarch64-static"
                self.qemu_arch_static = (f"/{qemu_arch_bin}",
                                        join(root, qemu_arch_bin))
        elif host_arch:
            self.profile = MNT_FULL

        self.paths = ()
        self.mounted: dict[str, bool] = {}

        for mount_item in sorted(self.profile):
            switch, host_mnt, chr_mnt = mount_item
            chr_mnt = join(root, chr_mnt)
            self.paths = tuple(
                    [*self.paths,
                     (switch, host_mnt, chr_mnt)
                     ]
                    )
            self.mounted[chr_mnt] = False
        self.mount()

    def mount(self) -> None:
        ''' mount this chroot

        Raises:
            MountError: An error occured while trying to mount chroot
        '''
        for switch, host_mnt, chr_mnt in self.paths:
            if is_mounted(chr_mnt):
                self.mounted[chr_mnt] = True
                continue
            try:
                subprocess.run(
                    ['mount', switch, host_mnt, chr_mnt],
                    check=True)
                self.mounted[chr_mnt] = True
            except subprocess.CalledProcessError as e:
                raise MountError(*e.args) from e
        if self.qemu_arch_static:
            shutil.copy(*self.qemu_arch_static)

    def umount(self) -> None:
        ''' un-mount this chroot

        Raises:
            MountError: An error occured while trying to un-mount chroot
        '''
        if self.qemu_arch_static:
            try:
                os.remove(self.qemu_arch_static[-1])
            except FileNotFoundError:
                pass
        for _, _, chr_mnt in reversed(self.paths):
            if self.mounted[chr_mnt]:
                subprocess.run(["umount", "-f", chr_mnt])
                self.mounted[chr_mnt] = False

    def __del__(self) -> None:
        self.umount()


class Chroot:
    '''represents a chroot on your system that you can run commands inside.
    This class automatically attempts to mount the given chroot.

    Example usage:

        >>> foo = Chroot('/path/to/chroot', { 'ENVVAR': 'bar' })
        >>> assert 'ENVVAR=bar' in foo.run(['env'], text=True).stdout
    '''
    def __init__(
            self, newroot: AnyPath,
            environ: dict[str, str] | None = None,
            mnt_profile: list[tuple[str, str, str]] | None = None
            ):
        if environ is None:
            environ = {}
        self.environ = {
            'HOME': '/root',
            'TERM': os.environ['TERM'],
            'LC_ALL': 'C',
            'PATH': "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/bin:/usr/sbin"
        }
        self.environ.update(environ)

        self.profile = MNT_DEFAULT if not mnt_profile else mnt_profile

        self.chr_path: str = realpath(os.fspath(newroot))
        self.path = self.chr_path # for backwards compatability
        self.magicmounts = MagicMounts(self.profile, self.chr_path)

    def _prepare_command(self, *commands: str) -> list[str]:
        if '>' in commands or '<' in commands or '|' in commands:
            raise ChrootError("Output redirects and pipes not supported in"
                              f"fab-chroot (command: `{commands}')")
        quoted_commands = []
        for command in commands:
            try:
                quoted_commands.append(shlex.quote(command))
            except TypeError as e:
                raise ChrootError(
                        f'failed to prepare command {command!r} for chroot'
                        ) from e
        return [
            'chroot', self.chr_path,
            'sh', '-c',
            ' '.join(quoted_commands)
        ]

    def system(self, command: str | None = None) -> int:
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

        debug('chroot.system (args) => \x1b[34m', repr(command), '\x1b[0m')
        command_chroot = ['chroot', self.chr_path, '/bin/bash']
        if command:
            command_chroot.extend(['-c', command])
        return subprocess.run(command_chroot, env=self.environ).returncode

    def run(self, command: str, *args: Any, **kwargs: Any
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
        debug('chroot.run (args) => \x1b[34m', repr(command), '\x1b[0m')
        cmd = self._prepare_command(*command)
        debug('chroot.run (prepared cmd) => \x1b[33m', repr(cmd), '\x1b[0m')
        return subprocess.run(cmd, env=self.environ, *args, **kwargs)
