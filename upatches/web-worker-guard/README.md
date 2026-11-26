# web-worker-guard

A BPF LSM upatch confining labeled PHP, Apache and nginx worker processes
against post-exploitation command execution and web-shell drop writes.

## Confinement policy

`Beefile` assigns policy bit `0x1` (`web-worker`) to `/usr/sbin/php-fpm*`,
`/usr/local/sbin/php-fpm`, `/usr/sbin/apache2`, `/usr/sbin/httpd`,
`/usr/local/apache2/bin/httpd`, `/usr/sbin/nginx` and
`/usr/local/nginx/sbin/nginx`. When any task carrying that inherited policy
bit runs:

- `lsm.s/bprm_check_security` refuses (`-EACCES`) executing interactive or
  command shells (`sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `csh`, `tcsh`,
  `busybox`), network fetch/relay tools (`curl`, `wget`, `nc`, `ncat`,
  `netcat`, `socat`) and general scripting runtimes (`python*`, `perl`,
  `perl5*`).
- `lsm/file_open` refuses (`-EACCES`) opening files ending in `.php`,
  `.php0`..`.php9`, `.pht`, `.phtml`, `.phar` or `.sh` (case-insensitively)
  with `FMODE_WRITE`.

## Limits

The checks look at a file's name, not at what the file is:

- The exec rule compares the last component of the path. A worker that
  copies `/bin/sh` to `/tmp/x`, or reaches it through a link of another
  name, executes it.
- The write rule runs when a file is opened. A worker that writes
  `shell.txt` and renames it to `shell.php` is not refused: no rename
  hook is attached.

The package raises the cost of the common web-shell and reverse-shell
payloads. It is not a boundary; `app-sandbox`, which decides by policy
label and not by name, is the one to use for that.

## Telemetry maps

- `activity` (`BPF_MAP_TYPE_PERCPU_ARRAY`, 1 entry): number of confined worker
  exec and writable-open checks evaluated.
- `hits` (`BPF_MAP_TYPE_PERCPU_ARRAY`, 1 entry): total refused exec or write
  attempts.
- `hits_by_kind` (`BPF_MAP_TYPE_PERCPU_ARRAY`, 2 entries): slot `0` counts
  refused `bprm_check_security` executions; slot `1` counts refused writable
  opens.

## Building

```sh
shirudo bpm build upatches/web-worker-guard --version 1.0.0 \
	--keys-dir <keys>
```
