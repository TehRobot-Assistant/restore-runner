# RestoreRunner

Continuous backup verification. Captures a point-in-time baseline of your source files, then periodically pulls a sample from the backup and compares it byte-for-byte to the baseline. Tells you whether your backup is restorable, or silently rotting.

**v0.1 supports restic only.** Borg + Kopia coming in v0.2.

## Quickstart (Unraid / Docker)

```bash
docker run -d --name restore-runner --restart unless-stopped \
  -p 127.0.0.1:8920:8920 \
  -v ./config:/config \
  -v /mnt/user/data:/srv/data:ro \
  tehrobot/restore-runner:latest
```

Open `http://<host>:8920/`. The wizard walks you through:

1. Create an admin user.
2. Add a backup repo (name, restic URL, password, source path).
3. Optional: change default cadence + apprise notification URLs in Settings.

No YAML config files. All state lives in `/config/restorerunner.db` (SQLite).

## How it works

- **On enrollment**: walks your source path and records file path, size, mtime, SHA-256 hash. Files matching `*.db`, `*.log`, etc are noted but not hashed (mutable — diffing them against a fixed hash is meaningless).
- **On each rehearsal**: picks N random non-mutable files from the baseline, pulls each from the backup via `restic dump`, hashes the restored bytes, compares to the baseline hash.
- **Structural check**: counts live files + total bytes, compares to baseline totals. A massive shortfall (e.g. live folder went empty — rsync's canonical silent failure) flags a **fail** even if every sampled file matched.
- **Reports**: `pass` (all matched + structural OK), `degraded` (some diverged/missing), `fail` (backup unreachable or source collapsed).

Notifications via [apprise](https://github.com/caronc/apprise) — 110+ services (ntfy, Discord, Slack, email, webhooks).

## Security

- Repo passwords are encrypted at rest (AES-256-GCM with a per-install master key stored in SQLite).
- Restic is invoked with `exec.CommandContext` + arg slice — no shell interpolation.
- Scratch files land in a 0700 tempdir created per-run with `os.MkdirTemp`. Files are removed immediately after hashing.
- Mount your source paths **read-only** in the compose file. RestoreRunner never writes to them.
- Compose constraints in the recommended shape: `read_only: true`, `tmpfs: /tmp`, `cap_drop: ALL`, `no-new-privileges:true`.

## What RestoreRunner is NOT

It doesn't claim "your backup is restorable." It claims "we sampled N files from your backup and compared against the enrollment baseline — all matched" or "K of N files diverged." A 30-file sample of a 20TB repo is a spot-check, not a guarantee.

## License

MIT.
