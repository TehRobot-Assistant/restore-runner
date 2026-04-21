# RestoreRunner

Upload an Unraid AppData Backup archive, boot the captured container in a
sandbox, watch its logs, one click to stop.

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
committing to a full restore into your live stack. Runs the recovered
container on a random host port with `--memory=1g --cpus=1.0
--cap-drop=ALL --security-opt no-new-privileges`, auto-stops after 10
minutes.

## Tunables

- `RR_MAX_UPLOAD_MB` (default `2048`)
- `RR_RUN_TIMEOUT_MIN` (default `10`)
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` — optional non-interactive admin seed

## Source + issues

https://github.com/TehRobot-Assistant/restore-runner

Licensed MIT.
