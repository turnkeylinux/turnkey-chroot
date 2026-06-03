# turnkey-chroot

A library to interact with and/or run commands in a chroot.

`turnkey-chroot` (Python module `chroot`) is a small wrapper around the system
`chroot` command. It sets up a chroot by mounting the required system paths
(`/proc`, `/sys`, `/dev`, `/dev/pts` & `/run`, or a custom profile), runs the
given command(s) inside the chroot, then unmounts everything again.

## Requirements

- Python 3.13+
- System utilities (invoked via `subprocess`):
    - `chroot` - `coreutils`
    - `mount` / `umount` - `mount`

Mounting and chrooting require root privileges.

## Common usage

The `mount` context manager handles set up and tear down of the system mounts
for you and yields a `Chroot` object:

```python
import chroot

with chroot.mount("/path/to/chroot") as mnt:
    # run a command, capturing its output (forwards to subprocess.run)
    proc = mnt.run(["ls", "-la", "/proc"], capture_output=True, text=True)
    print(proc.stdout)

    # run via a shell, returning only the exit code
    rc = mnt.system("apt-get update && apt-get -y upgrade")
```

Pass environment variables into the chroot via the `environ` argument:

```python
with chroot.mount("/path/to/chroot", environ={"DEBIAN_FRONTEND": "noninteractive"}) as mnt:
    mnt.system("apt-get -y install nginx")
```

The `Chroot` class can also be used directly (it mounts on instantiation):

```python
from chroot import Chroot

cr = Chroot("/path/to/chroot", environ={"ENVVAR": "bar"})
assert "ENVVAR=bar" in cr.run(["env"], capture_output=True, text=True).stdout
```

### Mount profiles

By default a `--type` based profile is used (`MNT_DEFAULT`). A bind-mount
profile (`MNT_FULL`, which also binds `/run` from the host) is also provided,
and a custom profile dict may be supplied via the `mnt_profile` argument.

### Debugging

Set the `TKL_CHROOT_DEBUG` environment variable (to any non-empty value) to
print the commands being run.

## Architecture

```
chroot/
  __init__.py     Module: mount context manager, Chroot + MagicMounts classes
  py.typed        PEP 561 marker (package ships inline type hints)
tests/
  test_chroot.py  Unit tests (no real mounting/root required)
```

## Tests

Tests use `pytest` (Debian: `python3-pytest`, PyPI: `pytest`). Run from the
project root:

```bash
python3 -m pytest
```

The suite mocks `subprocess` and the mount layer, so it needs neither root nor
a real chroot.
