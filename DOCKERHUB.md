# RestoreRunner

Upload an Unraid AppData Backup archive, boot the captured container in
a fully isolated sandbox, preview its WebUI inline, watch logs, one-click
stop.

## Quick start

```bash
docker run -d \
  --name restore-runner \
  -p 8922:8922 \
  -v $(pwd)/config:/config \
  -v /var/run/docker.sock:/var/run/docker.sock \
  tehrobot/restore-runner:latest
```

Open `http://<host>:8922` — create your admin via the first-run wizard,
then drop a `.zip` / `.rar` / `.tar` / `.tar.gz` / `.tar.zst` archive
onto the page.

## Why

Are your backups actually restorable? Find out in one click without
committing to a full restore into your live stack.

- **Ephemeral appdata.** Mounts always point at the uploaded archive's
  extract, never at your live `/mnt/user/appdata/*`.
- **Zero host-port publishing.** Sandboxes run on an internal docker
  network; the WebUI is reverse-proxied to your browser via
  `/run/<id>/preview/`.
- **No internet for the sandbox.** Apps that phone home on first boot
  will log network errors — that's intentional.
- `--memory=1g --cpus=1.0 --cap-drop=ALL --security-opt no-new-privileges`,
  auto-stops after 10 minutes.

## Tunables

- `RR_MAX_UPLOAD_MB` (default `2048`)
- `RR_RUN_TIMEOUT_MIN` (default `10`)
- `RR_HOST_DENY_PREFIXES` — comma-separated extra host paths the
  sandbox's mount-source assertion should reject
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` — optional non-interactive admin seed

## Source + issues

https://github.com/TehRobot-Assistant/restore-runner

Licensed MIT.
