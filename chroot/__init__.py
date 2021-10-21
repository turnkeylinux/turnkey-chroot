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

AnyPath = TypeVar('AnyPath', str, os.PathLike)

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
    raw_path: Union[str, bytes] = os.fspath(path)
    mode = 'rb' if isinstance(raw_path, bytes) else 'r'
    sep = b' ' if isinstance(raw_path, bytes) else ' '
    with open('/proc/mounts', mode) as fob:
        for line in fob:
            host, guest, *others = line.split(sep)
            if guest == path:
                return True
    return False


@contextmanager
def mount(
        target: os.PathLike,
        environ: Optional[Dict[str, str]] = None
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
    yield Chroot(target, environ)


class MagicMounts:
    '''MagicMounts: An object which manages mounting/unmounting a chroot.

    You *probably* don't want to use this object directly but rather the `mount`
    context manager, or the `Chroot` object.
    '''
    def __init__(self, root: str = "/", profile: Optional[str] = None):
        root = os.fspath(abspath(root))

        self.profile = 'default' if not profile else profile

        self.path['proc'] = join(root, "proc")
        self.path['dev'] = join(root, "dev")
        self.path['devpts'] = join(root, "dev/pts")
        self.path['sys'] = join(root, "sys")
        self.path['run'] = join(root, "run")

        self.mounted['proc'] = False
        self.mounted['dev'] = False
        self.mounted['devpts'] = False
        self.mounted['sys'] = False
        self.mounted['run'] = False

        if self.profile not in ['default', 'full']:
            raise MountError(f"Profile unknown: {profile}")

        self.mount()

    @staticmethod
    def _run(command):
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            raise MountError(*e.args) from e

    def mount(self) -> None:
        ''' mount this chroot

        Raises:
            MountError: An error occured while trying to mount chroot
        '''

        def default_mount(self, mtype: str, guest_mnt: str) -> None:
            if is_mounted(guest_mnt):
                return
            command = ['mount', '-t']
            self._run([*command, mtype, f'{mtype}-chroot', guest_mnt])
            self.mounted[mtype] = True

        def full_mount(self, host_mnt: str, guest_mnt: str) -> None:
            if is_mounted(guest_mnt):
                return
            command = ['mount', '-o', 'bind']
            self._run([*command, host_mnt, guest_mnt])
            self.mounted[host_mnt] = True

        if self.profile is 'default':
            for mtype, path in (('proc', self.path_proc),
                                ('devpts', self.path_dev_pts)):
                default_mount(mtype, path)
        elif self.profile is 'full':
            for host_mnt, guest_mnt in (('proc', self.path_proc),
                                        ('dev', self.path_dev),
                                        ('sys', self.path_sys),
                                        ('run', self.path_run))
                full_mount(host_mnt, guest_mnt)

    def umount(self) -> None:
        ''' un-mount this chroot

        Raises:
            MountError: An error occured while trying to un-mount chroot
        '''
        command = ['umount', '-f']
        for mount in self.mounted.keys():
            if self.mounted[mount]:
                self._run([*command, self.path[mount]]
                self.mounted[mount] = False

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
            environ: Optional[Dict[str, str]] = None):

        if environ is None:
            environ = {}
        self.environ = {
            'HOME': '/root',
            'TERM': os.environ['TERM'],
            'LC_ALL': 'C',
            'PATH': "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/bin:/usr/sbin"
        }
        self.environ.update(environ)

        self.path: str = realpath(os.fspath(newroot))
        self.magicmounts = MagicMounts(self.path)

    def _prepare_command(self, *commands: str) -> List[str]:
        quoted_commands = []
        for command in commands:
            try:
                quoted_commands.append(shlex.quote(command))
            except TypeError as e:
                raise ChrootError(f'failed to prepare command {command!r} for chroot') from e 
        return [
            'chroot', self.path,
            'sh', '-c',
            ' '.join(quoted_commands)
        ]
    
    def system(self, *command: str) -> int:
        """execute system command in chroot

        roughly analagous to `os.system` except within the context of a chroot
        (uses subprocess internally)

        Args:
            *command: command to run inside a chroot followed by args

        Returns:
            returncode of process as an int 

        Raises:
            FileNotFoundError: chroot program doesn't exist
        """

        debug('chroot.system (args) => \x1b[34m', repr(command), '\x1b[0m')
        cmd = self._prepare_command(*command)
        debug('chroot.system (prepared cmd) => \x1b[33m', repr(cmd), '\x1b[0m')
        return subprocess.run(cmd, env=self.environ).returncode

    def run(self, command: str, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
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
