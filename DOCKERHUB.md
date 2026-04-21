# RestoreRunner

**Continuous backup verification.** Captures a point-in-time baseline of your source files, then periodically pulls a sample from the backup and compares it byte-for-byte to the baseline. Tells you whether your backup is restorable, or silently rotting.

**v0.1 — restic only.** Borg + Kopia in v0.2.

## Run

```bash
docker run -d --name restore-runner --restart unless-stopped \
  -p 127.0.0.1:8920:8920 \
  -v ./config:/config \
  -v /mnt/user/data:/srv/data:ro \
  tehrobot/restore-runner:latest
```

Open `http://<host>:8920/`. Wizard creates an admin, then you add a repo.

## Why this exists

Every self-hoster backs up. Almost nobody verifies restores. Canonical failures:
- **rsync has been copying an empty folder for 8 weeks.** Nobody notices.
- **Restic snapshot can't be decrypted** after a key rotation.
- **S3 lifecycle policy moved old snapshots to Glacier** — listed, no longer restorable in <3 hrs.

`restic check --read-data` verifies the repo is internally consistent. It doesn't answer: **"if I had to restore, could I actually get the files back, identical to what I backed up?"**

RestoreRunner does.

## License

MIT. [Source on GitHub.](https://github.com/TehRobot-Assistant/restore-runner)
