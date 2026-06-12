# Overview

A Juju charm that deploys and manages [`auditd`][1] on machine. [`auditd`][1] is  the  userspace
component to the  Linux Auditing System. It's responsible for writing audit records to the disk.

## Platform Requirements

This charm can only be deployed on **bare metal machines or virtual machines**. It **cannot** be
deployed on Linux containers (LXC).

[`auditd`][1] performs kernel-level auditing and requires direct access to the kernel's audit
subsystem, which is not available within containers. The charm will automatically prevent
deployment on unsupported platforms (LXC containers) and raise an error during installation.

[1]: https://manpages.ubuntu.com/manpages/noble/man8/auditd.8.html

## Session Recording

The charm can record SSH sessions using [`tlog`][2]. When enabled, interactive and remote-command
SSH sessions opened by members of the configured groups are recorded to
`/var/log/tlog/sessions.log` and shipped to Loki via the existing Grafana Agent COS pipeline.

### Configuration

```
juju config auditd session_recording_groups="warthogs,bootstack-squad"
```

- Comma-separated Unix group names.
- Empty string (default) disables recording.
- sshd `Match Group` uses **OR-semantics**: a user is matched if their *primary or supplementary*
  group is in the list. Do not use broad system groups (`root`, `sudo`, `adm`, `users`, `nogroup`,
  `daemon`) - the charm rejects them to prevent accidentally recording far more users than intended.
- Requires `tlog` from the Ubuntu `universe` pocket. Ensure it is enabled before setting this option.

### Security caveats

- **Root can evade recording.** Root-equivalent users can bypass the `ForceCommand` wrapper
  (e.g. by running a second sshd with custom config). This is covered by auditd
  tamper-detection rules installed alongside session recording.
- **Recordings contain secrets.** Recording captures everything *displayed* in the terminal:
  commands as typed (echoed by the shell) and full program output (e.g. `cat admin.conf`,
  kubeconfigs, tokens). Passwords entered at non-echoing prompts (sudo, SSH) are not captured -
  terminal input recording is disabled. Before enabling, ensure that Loki has appropriate RBAC
  and data-retention policies so that tlog records are accessible only to authorised operators
  and are retained no longer than required.
- **File transfers are not recorded.** `scp`, `rsync`, and sftp sessions are passed through
  unrecorded (the tlog pty layer would corrupt binary framing). They are still covered by auditd
  path-watch rules.

### Replay

All sessions share one file; each recording is identified by its `rec` field. List the
recordings, then replay one:

```
# list recordings
sudo jq -r 'select(.id==1) | "\(.rec)  \(.user)  \(.time | todate)"' /var/log/tlog/sessions.log

# replay a specific recording
sudo tlog-play -r file -i /var/log/tlog/sessions.log -m "<rec-id>"
```

[2]: https://github.com/Scribery/tlog
